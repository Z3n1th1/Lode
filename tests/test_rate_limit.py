"""Tests for core.rate_limit — the one budget every worker draws from.

The bug this module exists to prevent is arithmetic, not logic: a per-call-site
sleep multiplies by the worker count, so eight workers turn a program's stated
3 req/s into 24.  A test that only checks "a single worker waits" would pass
against that bug, so the tests here are mostly about *aggregate* behaviour —
what the program on the other end actually sees.
"""
from __future__ import annotations

import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "core"))

from agents.surface_discovery import SurfaceScope, discover_surface  # noqa: E402
from console import jobs as console_jobs  # noqa: E402
from core.rate_limit import (  # noqa: E402
    HARD_MAX_REQUESTS_PER_RUN, MAX_REQUESTS_PER_RUN, REQUESTS_ENV, RequestBudget,
    TokenBucket, bucket_key, configure_persistence, configured_max_requests, limiter_for,
    reset_limiters,
)

DELAY = 0.05  # 20 req/s — small enough to keep the suite fast, big enough to time


def _scope(program: str = "shared-program", delay: float = DELAY) -> SurfaceScope:
    return SurfaceScope(
        program, "authorized",
        allowed_hosts=("a.example.com", "b.example.com", "c.example.com"),
        delay_seconds=delay,
    )


class _FakeJob:
    """Just enough of a JobRecord for the Console scope builders."""

    def __init__(self, *, target: str, turn_id: str = "", payload: dict | None = None) -> None:
        self.target = target
        self.turn_id = turn_id
        self.payload = payload or {}


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


class EngagementKeyingTests(unittest.TestCase):
    """预算的身份是 engagement,不是 program。

    ``program`` 是给人看的名字:Console 每个 job 铸一个新的(``console-<run_id>``)。
    拿它当桶的键 = 一个 job 一个桶,而"一次粘贴起 N 个 job"正是 Console 的主要
    用法 —— 于是程序写明的速率被静默乘以 N。这个类里的每一个断言,在旧键下都红。
    """

    def setUp(self) -> None:
        reset_limiters()
        self.addCleanup(reset_limiters)

    def test_engagement_wins_over_program(self) -> None:
        a = SurfaceScope("console-SA-1", "authorized", engagement="turn-T-abc",
                         allowed_hosts=("a.example.com",), delay_seconds=DELAY)
        b = SurfaceScope("console-SA-2", "authorized", engagement="turn-T-abc",
                         allowed_hosts=("a.example.com",), delay_seconds=DELAY)
        self.assertNotEqual(a.program, b.program)          # 显示名仍是每个 job 一个
        self.assertEqual(bucket_key(a), bucket_key(b))     # 钱包是同一个
        self.assertEqual("turn-T-abc", bucket_key(a))
        self.assertIs(limiter_for(a), limiter_for(b))

    def test_an_empty_engagement_falls_back_to_program(self) -> None:
        """CLI 那条路一个字都没变:scope 文件不声明 engagement,键仍是 program。"""
        self.assertEqual("shared-program", bucket_key(_scope()))
        self.assertEqual("other", bucket_key(_scope("other")))

    def test_two_conversations_are_two_engagements(self) -> None:
        """两次对话是两个承诺,不能因为名字像就并成一个桶。"""
        a = SurfaceScope("console-SA-1", "authorized", engagement="turn-T-1", allowed_hosts=("a.example.com",), delay_seconds=DELAY)
        b = SurfaceScope("console-SA-2", "authorized", engagement="turn-T-2", allowed_hosts=("a.example.com",), delay_seconds=DELAY)
        self.assertIsNot(limiter_for(a), limiter_for(b))


class ConsoleFanOutBudgetTests(unittest.TestCase):
    """端到端:一次粘贴的 N 个 job,从程序那一侧看只能有一个速率。"""

    def setUp(self) -> None:
        reset_limiters()
        self.addCleanup(reset_limiters)

    @staticmethod
    def _job(host: str, *, turn_id: str, run_id: str, delay: float = DELAY) -> SurfaceScope:
        job = _FakeJob(target=f"https://{host}/", turn_id=turn_id,
                       payload={"run_id": run_id, "delay_seconds": delay})
        return console_jobs._typed_target_scope(job, run_id=run_id, target_url=job.target)

    def test_two_jobs_of_one_turn_share_one_bucket(self) -> None:
        first = limiter_for(self._job("a.example.com", turn_id="T-abc", run_id="SA-1"))
        second = limiter_for(self._job("b.example.com", turn_id="T-abc", run_id="SA-2"))
        self.assertIs(first, second)

    def test_the_program_name_is_still_per_job_for_display(self) -> None:
        """修的是桶的键,不是显示名 —— 每个 job 上还是看得见它是哪一次运行。"""
        self.assertNotEqual(self._job("a.example.com", turn_id="T-abc", run_id="SA-1").program,
                            self._job("b.example.com", turn_id="T-abc", run_id="SA-2").program)

    def test_a_paste_does_not_multiply_the_program_rate(self) -> None:
        """4 个 job 各取 2 枚令牌,总耗时必须按 8 枚算。

        旧键是 program=console-<run_id>,一个 job 一个桶 —— 4 个桶各自第一次取用
        都是免费的,整段会在一个 DELAY 内跑完。共享之后必须 ≥ 7×DELAY。
        每个 worker 用**自己那个 scope** 取桶,这正是 agents/*.py 里的调用形状。
        """
        hosts = ("a", "b", "c", "d")

        def work(scope: SurfaceScope) -> None:
            limiter = limiter_for(scope)
            assert limiter is not None
            for _ in range(2):
                limiter.acquire(f"https://{hosts[0]}.example.com/")

        scopes = [self._job(f"{host}.example.com", turn_id="T-one-paste", run_id=f"SA-{host}")
                  for host in hosts]
        workers = [threading.Thread(target=work, args=(scope,)) for scope in scopes]
        started = time.monotonic()
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()
        self.assertGreaterEqual(time.monotonic() - started, 7 * DELAY * 0.8)


class CrossProcessBudgetTests(unittest.TestCase):
    """CLI 跑 --from-scope 的同时 Console 也在跑:两边必须花同一个钱包。

    内存里的 registry 只有自己进程的线程知道它。``reset_limiters()`` 在这里就是
    "另一个进程":它对这个桶一无所知,只认 state dir 里那个文件。
    """

    def setUp(self) -> None:
        reset_limiters()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(configure_persistence, None)
        self.addCleanup(reset_limiters)
        self.addCleanup(self.tmp.cleanup)
        configure_persistence(self.tmp.name)

    def _files(self) -> list:
        return sorted((Path(self.tmp.name) / "rate-limit").glob("*.json"))

    def test_a_second_process_does_not_get_a_fresh_bucket(self) -> None:
        scope = _scope()
        limiter = limiter_for(scope)
        assert limiter is not None
        url = "https://a.example.com/"
        for _ in range(3):          # 第一次免费,后两次各等一个 DELAY
            limiter.acquire(url)

        reset_limiters()            # ← 另一个进程,内存清零
        started = time.monotonic()
        reloaded = limiter_for(scope)
        assert reloaded is not None
        reloaded.acquire(url)
        # 只能来自文件:主机桶也是新铸的、空的,它不会拦。
        self.assertGreaterEqual(time.monotonic() - started, DELAY * 0.5)

    def test_a_different_engagement_is_a_different_file(self) -> None:
        for program in ("program-a", "program-b"):
            limiter = limiter_for(_scope(program))
            assert limiter is not None
            limiter.acquire("https://a.example.com/")
        self.assertEqual(2, len(self._files()))

    def test_the_file_says_whose_budget_it_is(self) -> None:
        """落盘的东西要能被人读懂:哪个 engagement、花了多少、按什么速率回填。"""
        limiter = limiter_for(_scope("prod-program"))
        assert limiter is not None
        limiter.acquire("https://a.example.com/")
        doc = json.loads(self._files()[0].read_text(encoding="utf-8"))
        self.assertEqual("prod-program", doc["key"])
        self.assertLess(float(doc["tokens"]), 1.0)
        self.assertAlmostEqual(1.0 / DELAY, float(doc["rate_per_second"]), places=3)

    def test_the_file_bucket_still_paces(self) -> None:
        limiter = limiter_for(_scope())
        assert limiter is not None
        started = time.monotonic()
        for _ in range(5):
            limiter.acquire("https://a.example.com/")
        self.assertGreaterEqual(time.monotonic() - started, 4 * DELAY * 0.8)

    def test_without_a_state_dir_nothing_is_written(self) -> None:
        """没配 state dir 就是老行为:内存桶,一个文件都不落(测试和库调用走这条)。"""
        configure_persistence(None)
        limiter = limiter_for(_scope())
        assert limiter is not None
        limiter.acquire("https://a.example.com/")
        self.assertEqual([], self._files())


class RequestBudgetTests(unittest.TestCase):
    """速率盖住"多快",这个盖住"多少" —— 平台红线要求"最小化"。

    在这之前单目标只受速率约束:20 圈 × (3 次探索 + 3 个动作 × 2 轮) ≈ 420 个请求,
    没有任何计数器。``JobContext.spend_request`` 存在但零调用者。
    """

    def test_a_fresh_budget_hands_out_exactly_its_limit(self):
        budget = RequestBudget(3)
        self.assertEqual([True, True, True, False, False],
                         [budget.spend() for _ in range(5)])
        self.assertEqual(3, budget.used)
        self.assertEqual(0, budget.remaining)
        self.assertTrue(budget.exhausted)

    def test_the_default_is_the_documented_number(self):
        budget = RequestBudget()
        self.assertEqual(MAX_REQUESTS_PER_RUN, budget.limit)
        self.assertEqual(MAX_REQUESTS_PER_RUN, configured_max_requests())

    def test_the_env_override_is_clamped_to_the_hard_max(self):
        import os
        from unittest.mock import patch

        with patch.dict(os.environ, {REQUESTS_ENV: "99999"}):
            self.assertEqual(HARD_MAX_REQUESTS_PER_RUN, configured_max_requests())
        with patch.dict(os.environ, {REQUESTS_ENV: "7"}):
            self.assertEqual(7, configured_max_requests())

    def test_garbage_does_not_mean_unlimited(self):
        import os
        from unittest.mock import patch

        for bad in ("", "  ", "lots", "-5", "0"):
            with self.subTest(value=bad), patch.dict(os.environ, {REQUESTS_ENV: bad}):
                self.assertEqual(MAX_REQUESTS_PER_RUN, configured_max_requests())

    def test_two_threads_cannot_spend_the_same_token_twice(self):
        budget = RequestBudget(50)
        granted = []
        lock = threading.Lock()

        def worker():
            local = []
            for _ in range(20):
                local.append(budget.spend())
            with lock:
                granted.extend(local)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(50, sum(1 for item in granted if item))
        self.assertEqual(50, budget.used)


if __name__ == "__main__":
    unittest.main()
