"""Tests for core.rate_limit — the one budget every worker draws from.

The bug this module exists to prevent is arithmetic, not logic: a per-call-site
sleep multiplies by the worker count, so eight workers turn a program's stated
3 req/s into 24.  A test that only checks "a single worker waits" would pass
against that bug, so the tests here are mostly about *aggregate* behaviour —
what the program on the other end actually sees.
"""
from __future__ import annotations

import sys
import threading
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "core"))

from agents.surface_discovery import SurfaceScope, discover_surface  # noqa: E402
from core.rate_limit import TokenBucket, limiter_for, reset_limiters  # noqa: E402

DELAY = 0.05  # 20 req/s — small enough to keep the suite fast, big enough to time


def _scope(program: str = "shared-program", delay: float = DELAY) -> SurfaceScope:
    return SurfaceScope(
        program, "authorized",
        allowed_hosts=("a.example.com", "b.example.com", "c.example.com"),
        delay_seconds=delay,
    )


class TokenBucketTests(unittest.TestCase):
    def test_it_paces_a_single_caller(self) -> None:
        bucket = TokenBucket(rate_per_second=50.0)  # capacity 1 → first take is free
        started = time.monotonic()
        for _ in range(5):
            bucket.acquire()
        # 4 further takes at 20ms each
        self.assertGreaterEqual(time.monotonic() - started, 4 * 0.02 - 0.01)

    def test_a_burst_has_to_be_asked_for(self) -> None:
        """默认容量 1:一次突发正是限速要防的东西,不能白送。"""
        bucket = TokenBucket(rate_per_second=1.0)
        started = time.monotonic()
        bucket.acquire()
        self.assertLess(time.monotonic() - started, 0.05)


class LimiterKeyingTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_limiters()
        self.addCleanup(reset_limiters)

    def test_two_workers_of_one_scope_share_one_bucket(self) -> None:
        """两个 worker 各持一个 SurfaceScope 实例,必须落到同一个桶上。

        这是这一层存在的全部理由。以前限速是调用点上的局部变量,worker 之间没有
        任何共享,所以并发度直接乘在程序承诺的 req/s 上。
        """
        self.assertIs(limiter_for(_scope()), limiter_for(_scope()))

    def test_a_different_program_is_a_different_promise(self) -> None:
        self.assertIsNot(limiter_for(_scope("program-a")), limiter_for(_scope("program-b")))

    def test_a_different_pace_is_a_different_promise(self) -> None:
        """同一个 program 的两份 pacing 是两句不同的话,合并会把第一句的速率
        静默套到第二句上。"""
        self.assertIsNot(limiter_for(_scope(delay=0.05)), limiter_for(_scope(delay=0.2)))

    def test_no_declared_pacing_means_no_limiter(self) -> None:
        """delay<=0 是 scope 自己说的"不限速",这一层必须彻底让开 ——
        零延时的 fixture 如果被加上等待,整套测试都会无故变慢。"""
        self.assertIsNone(limiter_for(_scope(delay=0.0)))
        self.assertIsNone(limiter_for(_scope(delay=-1.0)))


class AggregateRateTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_limiters()
        self.addCleanup(reset_limiters)

    def test_concurrent_callers_cannot_beat_the_program_rate(self) -> None:
        """4 个线程抢 8 个令牌,总耗时必须按 8 个令牌算,不是按每线程 2 个算。

        每个线程各持一个 scope 实例 —— 也就是 4 个 worker。若桶不是共享的,
        这里会在 ~0.1s 内跑完;共享之后必须 ≥ 7×DELAY。
        """
        limiter = limiter_for(_scope())
        assert limiter is not None

        def work(url: str) -> None:
            for _ in range(2):
                limiter.acquire(url)

        workers = [threading.Thread(target=work, args=(f"https://{host}/",))
                   for host in ("a", "b", "c", "d")]
        started = time.monotonic()
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()
        elapsed = time.monotonic() - started
        # 8 取用 → 7 个间隔;留 20% 余量给调度抖动(抖动只会让耗时更长,不会更短)
        self.assertGreaterEqual(elapsed, 7 * DELAY * 0.8)

    def test_one_host_cannot_absorb_the_whole_budget(self) -> None:
        """主机桶不比程序桶宽:同一台主机上的并发请求也要按同一个间隔排队。"""
        limiter = limiter_for(_scope())
        assert limiter is not None
        stamps: list[float] = []
        lock = threading.Lock()

        def work() -> None:
            for _ in range(3):
                limiter.acquire("https://a.example.com/")
                with lock:
                    stamps.append(time.monotonic())

        workers = [threading.Thread(target=work) for _ in range(3)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()
        stamps.sort()
        gaps = [b - a for a, b in zip(stamps, stamps[1:])]
        self.assertGreaterEqual(min(gaps), DELAY * 0.8)


class ScannerHonoursTheBudgetTests(unittest.TestCase):
    """端到端:两个并发的建面扫描,从程序那一侧看只能有一个速率。"""

    def setUp(self) -> None:
        reset_limiters()
        self.addCleanup(reset_limiters)

    def test_two_concurrent_scans_share_one_budget(self) -> None:
        scope = _scope()  # 两个线程共用同一个 scope —— 正是并发 worker 的形状
        stamps: list[float] = []
        lock = threading.Lock()

        def fetch(url: str, *, timeout: float, max_bytes: int = 0):
            with lock:
                stamps.append(time.monotonic())
            return 200, "<html><body><a href='/x'>x</a></body></html>", {}

        errors: list[BaseException] = []

        def scan(target: str) -> None:
            try:
                discover_surface(scope, target, fetcher=fetch, max_scripts=1)
            except BaseException as exc:  # noqa: BLE001 - surface in the assert below
                errors.append(exc)

        workers = [threading.Thread(target=scan, args=(f"https://{host}/",))
                   for host in ("a.example.com", "b.example.com")]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()

        self.assertEqual([], errors)
        self.assertGreaterEqual(len(stamps), 3, "测试本身没跑出足够的请求,结论无效")
        stamps.sort()
        gaps = [b - a for a, b in zip(stamps, stamps[1:])]
        self.assertGreaterEqual(min(gaps), DELAY * 0.8)


if __name__ == "__main__":
    unittest.main()
