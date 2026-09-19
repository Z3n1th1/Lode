"""Tests for core.job_runner — bounded, restart-safe, cooperative job execution."""
from __future__ import annotations

import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "core"))

from core import job_registry as jr  # noqa: E402
from core.job_runner import (  # noqa: E402
    DEFAULT_JOB_WORKERS,
    MAX_JOB_WORKERS,
    JobRunner,
    configured_job_workers,
)


def _wait(cond, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(0.01)
    return False


class JobRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.registry = jr.JobRegistry(Path(self._tmp.name) / "jobs")
        self.events: list = []
        self.notified: list = []
        self.addCleanup(self._tmp.cleanup)

    def _runner(self, handlers, **kwargs):
        runner = JobRunner(
            registry=self.registry, handlers=handlers,
            on_event=lambda sid, kind, payload: self.events.append((sid, kind, payload)),
            notify_fn=lambda jid, status: self.notified.append((jid, status)),
            max_phases=3, retry_backoff=0.01, **kwargs,
        )
        self.addCleanup(runner.shutdown)
        return runner

    def test_successful_job_completes_and_emits(self) -> None:
        def handler(job, ctx):
            ctx.progress(phase="recon")
            return {"summary_ref": "sum-1"}

        runner = self._runner({"scan": handler})
        job = self.registry.create(session_id="s1", turn_id="T-1", kind="scan", target="t")
        runner.submit(job)
        self.assertTrue(_wait(lambda: (self.registry.get(job.job_id) or job).status == jr.COMPLETED))
        final = self.registry.get(job.job_id)
        self.assertEqual("sum-1", final.summary_ref)
        self.assertEqual("recon", final.progress.get("phase"))
        kinds = [k for _, k, _ in self.events]
        self.assertIn("subtask_started", kinds)
        self.assertIn("subtask_finished", kinds)
        self.assertEqual([(job.job_id, jr.COMPLETED)], self.notified)

    def test_no_handler_fails_fast(self) -> None:
        runner = self._runner({})
        job = self.registry.create(kind="unknown")
        runner.submit(job)
        self.assertTrue(_wait(lambda: self.registry.get(job.job_id).status == jr.FAILED))
        self.assertEqual("no_handler:unknown", self.registry.get(job.job_id).error)

    def test_handler_exception_retries_then_fails_closed(self) -> None:
        attempts = {"n": 0}

        def handler(job, ctx):
            attempts["n"] += 1
            raise RuntimeError("boom")

        runner = self._runner({"scan": handler})
        job = self.registry.create(kind="scan")
        runner.submit(job)
        self.assertTrue(_wait(lambda: self.registry.get(job.job_id).status == jr.FAILED))
        self.assertEqual(3, attempts["n"])  # max_phases retries
        self.assertIn("RuntimeError", self.registry.get(job.job_id).error)

    def test_retry_recovers_on_second_phase(self) -> None:
        attempts = {"n": 0}

        def handler(job, ctx):
            attempts["n"] += 1
            if attempts["n"] == 1:
                raise RuntimeError("transient")
            return {"summary_ref": "ok"}

        runner = self._runner({"scan": handler})
        job = self.registry.create(kind="scan")
        runner.submit(job)
        self.assertTrue(_wait(lambda: self.registry.get(job.job_id).status == jr.COMPLETED))
        self.assertEqual(2, attempts["n"])

    def test_stop_is_cooperative(self) -> None:
        started = threading.Event()

        def handler(job, ctx):
            started.set()
            for _ in range(500):
                if ctx.stopped():
                    return {"stopped_early": True}
                time.sleep(0.01)
            return {}

        runner = self._runner({"scan": handler})
        job = self.registry.create(kind="scan")
        runner.submit(job)
        self.assertTrue(started.wait(timeout=5))
        runner.stop(job.job_id)
        # handler returns on stop, but the runner marks it failed("stopped")
        self.assertTrue(_wait(lambda: self.registry.get(job.job_id).status in jr.TERMINAL))
        self.assertEqual(jr.FAILED, self.registry.get(job.job_id).status)
        self.assertEqual("stopped", self.registry.get(job.job_id).error)

    def test_submit_after_shutdown_is_rejected(self) -> None:
        runner = self._runner({"scan": lambda job, ctx: {}})
        runner.shutdown()
        job = self.registry.create(kind="scan")
        with self.assertRaises(RuntimeError):
            runner.submit(job)


class JobPoolConcurrencyTests(unittest.TestCase):
    """池子的**并发度**本身是被测对象,不只是"job 能跑完"。

    以前是写死的 2:粘 20 个目标时 2 个在跑、18 个排队,而且没有任何地方会
    告诉你少跑了。所以这里断言的是"同一时刻真的有 N 个在跑"。
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.addCleanup(os.environ.pop, "LODE_JOB_WORKERS", None)
        os.environ.pop("LODE_JOB_WORKERS", None)
        self.registry = jr.JobRegistry(Path(self._tmp.name) / "jobs")

    def _run_all(self, *, workers, count):
        """用一道 3 人闸门证明确实同时在跑 —— 池子不够宽时闸门会超时并让 job 失败。"""
        gate = threading.Barrier(count, timeout=8)
        seen: list = []

        def handler(job, ctx):
            seen.append(job.job_id)
            gate.wait()  # 只有 count 个 job 同时在跑,才会一起放行
            return {}

        runner = JobRunner(registry=self.registry, handlers={"scan": handler},
                           on_event=None, notify_fn=None, max_workers=workers)
        self.addCleanup(runner.shutdown)
        jobs = [self.registry.create(kind="scan") for _ in range(count)]
        for job in jobs:
            runner.submit(job)
        done = _wait(lambda: all(
            (self.registry.get(j.job_id) or j).status in jr.TERMINAL for j in jobs), timeout=15)
        self.assertTrue(done, "job 没在超时内收尾")
        return [self.registry.get(j.job_id) for j in jobs], seen

    def test_three_jobs_run_at_the_same_time(self) -> None:
        records, seen = self._run_all(workers=3, count=3)
        self.assertEqual(3, len(seen), "3 个 job 没有同时进入 handler —— 池子没有真的并发")
        self.assertEqual([jr.COMPLETED] * 3, [r.status for r in records],
                         [r.error for r in records])

    def test_the_default_pool_is_wide_enough_for_a_scope_batch(self) -> None:
        """默认值必须明显大于 2,否则"多并发"只是文档里的一句话。"""
        self.assertGreaterEqual(configured_job_workers(), 4)

    def test_the_env_var_sets_the_pool(self) -> None:
        os.environ["LODE_JOB_WORKERS"] = "5"
        self.assertEqual(5, configured_job_workers())
        runner = JobRunner(registry=self.registry, handlers={}, on_event=None, notify_fn=None)
        self.addCleanup(runner.shutdown)
        self.assertEqual(5, runner.max_workers)

    def test_an_explicit_value_beats_the_env(self) -> None:
        """测试要能钉死一个确定值,不能跟着操作员的环境变量飘。"""
        os.environ["LODE_JOB_WORKERS"] = "5"
        runner = JobRunner(registry=self.registry, handlers={}, on_event=None,
                           notify_fn=None, max_workers=2)
        self.addCleanup(runner.shutdown)
        self.assertEqual(2, runner.max_workers)

    def test_garbage_and_absurd_values_fall_back(self) -> None:
        os.environ["LODE_JOB_WORKERS"] = "eight"
        self.assertEqual(DEFAULT_JOB_WORKERS, configured_job_workers())
        os.environ["LODE_JOB_WORKERS"] = "0"
        self.assertEqual(1, configured_job_workers())
        os.environ["LODE_JOB_WORKERS"] = "100000"
        self.assertEqual(MAX_JOB_WORKERS, configured_job_workers())


if __name__ == "__main__":
    unittest.main()
