"""Tests for the concurrent explore phase in agents.src_agent.

The reason this needs its own file: the failure mode of "concurrency" is not an
exception, it is *nothing happening* — the batch still returns three results, it
just took three times as long, and every assertion about results still passes.  So
these tests assert on **overlap** (were two things actually in flight at once),
and each one is paired with the serial setting so it would fail if the knob did
nothing.
"""
from __future__ import annotations

import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT))
sys.path.insert(0, str(_PROJECT_ROOT / "core"))

from agents.src_agent import (  # noqa: E402
    MAX_PARALLEL_EXPLORE,
    AgentConfig,
    ExploreResult,
    SrcAgentLoop,
    run_src_agent,
)
from agents.surface_discovery import SurfaceScope  # noqa: E402
from core.src_blackboard import SrcBlackboard  # noqa: E402

LLM_DELAY = 0.25


def _scope() -> SurfaceScope:
    return SurfaceScope(
        program="parallel-test", authorization="written authorization for test",
        allowed_domains=("example.com",), delay_seconds=0.0, timeout_seconds=5.0,
    )


def _seed(bb: SrcBlackboard, n: int) -> List[str]:
    bb.sync_candidates([
        {"candidate_id": f"SC-{i:03d}", "url": f"https://example.com/e{i}",
         "priority": 80 - i, "sources": ["openapi"]}
        for i in range(n)
    ], run_id="seed")
    return [row["intent_id"] for row in bb.snapshot()["intents"]]


def _overlap(intervals: List[tuple]) -> int:
    """How many intervals were in flight at the busiest moment."""
    events = [(start, 1) for start, _ in intervals] + [(end, -1) for _, end in intervals]
    events.sort()
    live = best = 0
    for _, delta in events:
        live += delta
        best = max(best, live)
    return best


class ExploreOverlapTests(unittest.TestCase):
    """一路跑到 LLM 那一层,因为并发只发生在那里。"""

    def _run(self, *, parallel: int, intents: int = 3):
        with tempfile.TemporaryDirectory() as tmp:
            bb_path = Path(tmp) / "bb.json"
            bb = SrcBlackboard(bb_path)
            intent_ids = _seed(bb, intents)
            intervals: List[tuple] = []
            lock = threading.Lock()

            def complete(system: str, user: str, **kwargs: Any):
                if "Reasoner" in system:
                    return json.dumps({
                        "reasoning": "fan out",
                        "selected_intents": [
                            {"intent_id": i, "hypothesis": "h", "check_description": "c"}
                            for i in intent_ids
                        ],
                        "should_stop": False,
                    })
                started = time.monotonic()
                time.sleep(LLM_DELAY)
                with lock:
                    intervals.append((started, time.monotonic()))
                return json.dumps({"analysis": "looked", "findings": [], "http_actions": []})

            def fetcher(url: str, *, timeout: float, max_bytes: int = 0):
                return 200, "<html><body>ok</body></html>", {}

            started = time.monotonic()
            summary = run_src_agent(
                bb_path, _scope(), max_cycles=1, max_explore_per_cycle=intents,
                max_parallel_explore=parallel, fetcher=fetcher,
                llm_complete_fn=complete, worker_id="w",
            )
            return summary, intervals, time.monotonic() - started

    def test_three_intents_are_in_flight_at_once(self) -> None:
        """并发度 3 时必须真的有 3 个 Explore 同时在飞。

        串行实现同样会"返回 3 个结果" —— 只是慢 3 倍。所以断言的是重叠数,
        不是结果数。"""
        summary, intervals, _ = self._run(parallel=3)
        self.assertEqual(3, len(intervals), summary)
        self.assertEqual(3, _overlap(intervals),
                         "3 个 Explore 没有真正重叠 —— 并发没生效")

    def test_serial_is_still_available_and_really_serial(self) -> None:
        """max_parallel_explore=1 必须回到老行为,否则这条开关是装饰。"""
        _, intervals, elapsed = self._run(parallel=1)
        self.assertEqual(1, _overlap(intervals))
        self.assertGreaterEqual(elapsed, 3 * LLM_DELAY * 0.8)

    def test_concurrency_is_what_makes_it_faster(self) -> None:
        _, _, serial = self._run(parallel=1)
        _, _, concurrent = self._run(parallel=3)
        self.assertLess(concurrent, serial * 0.75,
                        f"并发没带来提速:串行 {serial:.2f}s / 并发 {concurrent:.2f}s")


class ExploreBatchContractTests(unittest.TestCase):
    """``_explore_batch`` 的契约:顺序确定、单条崩了不拖垮整批。"""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.loop_ = SrcAgentLoop(AgentConfig(
            blackboard_path=Path(self._tmp.name) / "bb.json",
            scope=_scope(), max_parallel_explore=3,
        ))

    def test_results_come_back_in_planned_order_not_completion_order(self) -> None:
        """第一个故意最慢。按完成顺序返回的话,测试的计数、时间线、错误表
        都会随线程调度变化,一次运行就不再可复现。"""
        planned = [("I-1", "h1", "c1"), ("I-2", "h2", "c2"), ("I-3", "h3", "c3")]
        delays = {"I-1": 0.30, "I-2": 0.15, "I-3": 0.0}

        def fake_explore(intent_id, hypothesis, check, snapshot):
            time.sleep(delays[intent_id])
            return ExploreResult(intent_id, "dead_end", dead_end_reason="done")

        original = self.loop_._explore
        self.loop_._explore = fake_explore  # type: ignore[method-assign]
        try:
            results = self.loop_._explore_batch(planned, {})
        finally:
            self.loop_._explore = original  # type: ignore[method-assign]
        self.assertEqual(["I-1", "I-2", "I-3"], [r.intent_id for r in results])

    def test_one_crashing_intent_does_not_sink_the_batch(self) -> None:
        planned = [("I-1", "h1", "c1"), ("I-2", "h2", "c2"), ("I-3", "h3", "c3")]

        def fake_explore(intent_id, hypothesis, check, snapshot):
            if intent_id == "I-2":
                raise RuntimeError("boom")
            return ExploreResult(intent_id, "fact_added")

        original = self.loop_._explore
        self.loop_._explore = fake_explore  # type: ignore[method-assign]
        try:
            results = self.loop_._explore_batch(planned, {})
        finally:
            self.loop_._explore = original  # type: ignore[method-assign]

        by_id = {r.intent_id: r for r in results}
        self.assertEqual(3, len(results))
        self.assertEqual("fact_added", by_id["I-1"].status)
        self.assertEqual("fact_added", by_id["I-3"].status)
        self.assertEqual("error", by_id["I-2"].status)
        self.assertIn("boom", by_id["I-2"].dead_end_reason)

    def test_an_empty_batch_is_not_an_error(self) -> None:
        self.assertEqual([], self.loop_._explore_batch([], {}))


class ActivationRaceTests(unittest.TestCase):
    """激活路径是"先查再写",并发起 explore 之后必须加锁。"""

    def test_concurrent_activation_of_the_same_card_happens_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            loop = SrcAgentLoop(AgentConfig(
                blackboard_path=Path(tmp) / "bb.json", scope=_scope(),
                skill_pack="pentest",
            ))
            from core import skills as _skills
            modules = [m for m in _skills.signal_modules(
                "SQL 注入 XSS SSRF 越权 文件上传 命令注入", limit=6, pack="pentest")]
            self.assertGreaterEqual(len(modules), 2, "测试需要至少两篇可激活的打法")

            errors: List[BaseException] = []

            def work() -> None:
                try:
                    for _ in range(5):
                        loop.activate(modules, source="race-test")
                        loop._activated_section()
                except BaseException as exc:  # noqa: BLE001
                    errors.append(exc)

            threads = [threading.Thread(target=work) for _ in range(4)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            self.assertEqual([], errors)
            names = [row["name"] for row in loop._activation_log]
            self.assertEqual(sorted(set(names)), sorted(names),
                             "同一篇打法被激活了多次")
            self.assertEqual({}, {n: c for n, c in
                                  ((n, names.count(n)) for n in set(names)) if c > 1})

    def test_the_parallel_knob_is_validated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for bad in (0, -1, MAX_PARALLEL_EXPLORE + 1):
                with self.assertRaises(ValueError):
                    SrcAgentLoop(AgentConfig(
                        blackboard_path=Path(tmp) / "bb.json", scope=_scope(),
                        max_parallel_explore=bad,
                    ))


if __name__ == "__main__":
    unittest.main()
