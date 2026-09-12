from __future__ import annotations

import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from agents.src_autopilot import SrcAutopilot
from agents.surface_discovery import SurfaceScope
from core.src_blackboard import SrcBlackboard


class SrcAutopilotTests(unittest.TestCase):
    def _scope(self) -> SurfaceScope:
        return SurfaceScope(
            "fixture-src",
            "written authorization fixture",
            allowed_domains=("example.com",),
            delay_seconds=0.1,
        )

    def _result(self) -> dict:
        return {
            "schema": "SrcSurfaceResult/v1",
            "target": "https://example.com/",
            "base_url": "https://example.com",
            "paths": [
                "/api/v1/users?token=secret-value",
                "/admin/export?customer_id=123",
                "/health",
            ],
            "api_urls": ["https://api.example.com/graphql?sig=private-signature"],
            "sources": {
                "/api/v1/users?token=secret-value": ["openapi"],
                "/admin/export?customer_id=123": ["js"],
            },
        }

    def test_first_round_builds_prioritized_deduplicated_queue_without_persisting_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            agent = SrcAutopilot(self._scope(), root / "state.json", root / "out", max_rounds=3)
            summary = agent.run_round(["https://example.com"], results=[self._result()])
            candidates = json.loads((root / "out" / "src-autopilot-candidates.json").read_text(encoding="utf-8"))["candidates"]

        self.assertEqual("awaiting_next_round", summary["status"])
        self.assertEqual(4, summary["candidate_count"])
        self.assertGreaterEqual(candidates[0]["priority"], candidates[-1]["priority"])
        serialized = json.dumps(candidates, ensure_ascii=False)
        self.assertNotIn("secret-value", serialized)
        self.assertNotIn("private-signature", serialized)
        self.assertIn("token=[redacted]", serialized)
        self.assertTrue(all(item["requires_human_review"] for item in candidates))

    def test_duplicate_round_converges_and_restart_does_not_repeat_network_work(self) -> None:
        calls = []

        def discover(scope, target, *, max_scripts):
            calls.append((target, max_scripts))
            return self._result()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            agent = SrcAutopilot(
                self._scope(), root / "state.json", root / "out", max_rounds=4,
                discover_fn=discover,
            )
            first = agent.run_round(["https://example.com"])
            second = agent.run_round(results=[self._result()])
            restarted = SrcAutopilot(
                self._scope(), root / "state.json", root / "out", max_rounds=4,
                discover_fn=lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("network replay")),
            )
            third = restarted.run_round(results=[self._result()])
            fourth = restarted.run_round(results=[self._result()])

        self.assertEqual(1, len(calls))
        self.assertEqual("awaiting_next_round", first["status"])
        self.assertEqual("awaiting_next_round", second["status"])
        self.assertEqual("stopped", third["status"])
        self.assertEqual("converged_no_new_candidates", third["stop_reason"])
        self.assertEqual("already_terminal", fourth["event"])

    def test_out_of_scope_result_is_blocked_without_adding_candidates(self) -> None:
        result = self._result()
        result["base_url"] = "https://outside.example.net"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            agent = SrcAutopilot(self._scope(), root / "state.json", root / "out")
            summary = agent.run_round(["https://example.com"], results=[result])
            state = json.loads((root / "state.json").read_text(encoding="utf-8"))

        self.assertEqual(0, summary["candidate_count"])
        self.assertEqual(1, state["rounds"][0]["blocked_candidates"])

    def test_missing_authorization_and_unbounded_limits_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "surface_authorization_required"):
            SrcAutopilot(
                SurfaceScope("fixture", "", allowed_domains=("example.com",)),
                Path(tempfile.gettempdir()) / "src-auto-state.json",
                Path(tempfile.gettempdir()) / "src-auto-out",
            )
        with self.assertRaisesRegex(ValueError, "max_rounds"):
            SrcAutopilot(self._scope(), Path("state.json"), Path("out"), max_rounds=99)

    def test_blackboard_mirror_and_concurrent_rounds_keep_state_consistent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            agent = SrcAutopilot(self._scope(), root / "state.json", root / "out", max_rounds=4)
            with ThreadPoolExecutor(max_workers=2) as pool:
                summaries = list(pool.map(lambda _: agent.run_round(["https://example.com"], results=[self._result()]), [1, 2]))
            state = json.loads((root / "state.json").read_text(encoding="utf-8"))
            board = SrcBlackboard(root / "src-blackboard.json").snapshot()

        self.assertEqual({1, 2}, {item["round"] for item in state["rounds"]})
        self.assertEqual(2, state["current_round"])
        self.assertEqual(4, len(board["intents"]))
        self.assertEqual(4, len(board["facts"]))
        self.assertEqual(2, len(summaries))

    def test_single_round_run_accepts_default_convergence_window(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            agent = SrcAutopilot(self._scope(), root / "state.json", root / "out", max_rounds=1)
            summary = agent.run_round(["https://example.com"], results=[self._result()])
        self.assertEqual("stopped", summary["status"])
        self.assertEqual("max_rounds", summary["stop_reason"])


if __name__ == "__main__":
    unittest.main()
