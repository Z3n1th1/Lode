"""Tests for core.job_runner — bounded, restart-safe, cooperative job execution."""
from __future__ import annotations

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
from core.job_runner import JobRunner  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
