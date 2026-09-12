"""Project-level auto-retry: a transient phase failure must be retried, not
fail the target on the first blip (memfit-style fail→retry)."""
from __future__ import annotations

import asyncio
import unittest

from core.orchestrator import Orchestrator, TargetContext


class PhaseRetryTests(unittest.TestCase):
    def _orch(self, fn, notes):
        orch = Orchestrator(on_notify=lambda lv, msg: notes.append(msg), src_agent_fn=fn)
        orch.PHASE_RETRY_BACKOFF = 0  # keep the test fast
        return orch

    def test_phase_retries_transient_failure_then_succeeds(self) -> None:
        calls = {"n": 0}
        notes: list[str] = []

        def flaky(target_id, phase):
            calls["n"] += 1
            if calls["n"] < 3:
                raise RuntimeError("boom")
            return {"stop_reason": "no_queued_intents"}

        orch = self._orch(flaky, notes)
        ctx = TargetContext(target_id="t1")
        needs_human = asyncio.run(orch._phase(ctx, "triage"))

        self.assertFalse(needs_human)
        self.assertEqual(3, calls["n"])
        self.assertTrue(any("自动重跑" in note for note in notes), notes)

    def test_phase_gives_up_after_attempt_cap(self) -> None:
        calls = {"n": 0}
        notes: list[str] = []

        def always_fail(target_id, phase):
            calls["n"] += 1
            raise RuntimeError("permanent")

        orch = self._orch(always_fail, notes)
        ctx = TargetContext(target_id="t2")
        with self.assertRaises(RuntimeError):
            asyncio.run(orch._phase(ctx, "triage"))
        self.assertEqual(orch.PHASE_MAX_ATTEMPTS, calls["n"])


if __name__ == "__main__":
    unittest.main()
