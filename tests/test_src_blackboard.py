from __future__ import annotations

import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from core.src_blackboard import SrcBlackboard


class SrcBlackboardTests(unittest.TestCase):
    def test_sync_claim_and_finish_are_single_worker_and_replayable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            board = SrcBlackboard(Path(tmp) / "src-blackboard.json", default_lease_seconds=60)
            candidates = [{
                "candidate_id": "SC-001", "url": "https://example.com/admin/export?token=[redacted]",
                "priority": 80, "sources": ["openapi"], "next_phase": "C-human-gated-verification",
            }]
            self.assertEqual({"facts_added": 1, "intents_added": 1}, board.sync_candidates(candidates, run_id="SA-1"))
            self.assertEqual({"facts_added": 0, "intents_added": 0}, board.sync_candidates(candidates, run_id="SA-1"))

            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda worker: board.claim_next(worker), ["worker-a", "worker-b"]))
            claimed = [item for item in results if item is not None]
            self.assertEqual(1, len(claimed))
            claim = claimed[0]
            self.assertEqual("claimed", claim["intent"]["status"])
            owner = claim["claim"]["worker_id"]
            with self.assertRaisesRegex(ValueError, "claim_not_owned"):
                board.finish(claim["intent"]["intent_id"], "other-worker")
            board.heartbeat(claim["intent"]["intent_id"], owner)
            board.finish(claim["intent"]["intent_id"], owner, result_ref="local-result.json")
            snapshot = board.snapshot()

        self.assertEqual("completed", snapshot["intents"][0]["status"])
        self.assertEqual([], snapshot["claims"])
        self.assertNotIn("local-result.json", snapshot["events"][-1])
        self.assertNotIn("token", snapshot["events"][-1].get("detail", ""))

    def test_expired_lease_is_requeued(self) -> None:
        clock = [100.0]
        with tempfile.TemporaryDirectory() as tmp:
            board = SrcBlackboard(Path(tmp) / "src-blackboard.json", now_fn=lambda: clock[0], default_lease_seconds=5)
            board.sync_candidates([{"candidate_id": "SC-002", "url": "https://example.com/api", "priority": 40}], run_id="SA-2")
            first = board.claim_next("worker-a")
            self.assertIsNotNone(first)
            clock[0] = 106.0
            second = board.claim_next("worker-b")
            self.assertIsNotNone(second)
            self.assertEqual("worker-b", second["claim"]["worker_id"])

    def test_blackboard_redacts_runner_supplied_url_and_notes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            board = SrcBlackboard(Path(tmp) / "src-blackboard.json")
            board.sync_candidates([{
                "candidate_id": "SC-003", "url": "https://example.com/export?token=raw-secret&customer=123",
                "priority": 20,
            }], run_id="SA-3")
            claim = board.claim_next("worker-a")
            self.assertIsNotNone(claim)
            intent_id = claim["intent"]["intent_id"]
            board.add_hint(intent_id, "authorization: Bearer raw-secret", source="runner")
            board.add_dead_end(intent_id, "secret=raw-secret", detail="password=another-secret")
            snapshot = board.snapshot()
        serialized = json.dumps(snapshot, ensure_ascii=False)
        self.assertNotIn("raw-secret", serialized)
        self.assertNotIn("another-secret", serialized)
        self.assertIn("token=[redacted]", serialized)


class SrcBlackboardRetryAndDagTests(unittest.TestCase):
    """memfit-inspired: transient failures retry; intents form a dependency DAG."""

    def test_fail_requeues_then_dead_ends_after_cap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            board = SrcBlackboard(Path(tmp) / "bb.json", default_lease_seconds=60)
            board.sync_candidates(
                [{"candidate_id": "SC-A", "url": "https://example.com/a", "priority": 90}],
                run_id="r",
            )
            claim = board.claim_next("w1")
            self.assertIsNotNone(claim)
            iid = claim["intent"]["intent_id"]

            first = board.fail(iid, "w1", "fetch_error:timeout")
            self.assertEqual("queued", first["status"])
            self.assertEqual(1, first["attempts"])

            board.claim_next("w1")
            board.fail(iid, "w1", "fetch_error:timeout")
            board.claim_next("w1")
            third = board.fail(iid, "w1", "fetch_error:timeout")

            self.assertEqual("dead_end", third["status"])
            self.assertEqual(3, third["attempts"])
            snapshot = board.snapshot()
            self.assertEqual([], snapshot["claims"])
            self.assertTrue(any(d["intent_id"] == iid for d in snapshot["dead_ends"]))

    def test_dependency_blocks_claim_until_resolved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            board = SrcBlackboard(Path(tmp) / "bb.json", default_lease_seconds=60)
            board.sync_candidates(
                [
                    {"candidate_id": "SC-A", "url": "https://example.com/a", "priority": 90},
                    {"candidate_id": "SC-B", "url": "https://example.com/b", "priority": 80},
                ],
                run_id="r",
            )
            ids = [item["intent_id"] for item in board.snapshot()["intents"]]
            first, second = ids[0], ids[1]
            board.set_dependencies(second, [first])

            got = board.claim_next("w1")
            self.assertIsNotNone(got)
            self.assertEqual(first, got["intent"]["intent_id"])
            # The dependent intent must not be claimable yet.
            self.assertIsNone(board.claim_next("w2"))

            board.finish(first, "w1", status="completed")
            got2 = board.claim_next("w2")
            self.assertIsNotNone(got2)
            self.assertEqual(second, got2["intent"]["intent_id"])


class SrcBlackboardTimelineWorkmemTests(unittest.TestCase):
    """yaklang-inspired: append-only bucketed timeline + TODO-delta working memory."""

    def test_timeline_append_view_and_compress(self) -> None:
        clock = [1000.0]
        with tempfile.TemporaryDirectory() as tmp:
            board = SrcBlackboard(Path(tmp) / "bb.json", now_fn=lambda: clock[0])
            for i in range(5):
                clock[0] = 1000.0 + i * 60
                board.timeline_append("fetch", intent_id=f"I-{i}", summary=f"GET {i}")

            view = board.timeline_view(limit=10, bucket_minutes=3)
            self.assertEqual(5, view["total"])
            self.assertGreaterEqual(len(view["blocks"]), 2)  # absolute-time buckets

            head = board.timeline_compress(keep=2)
            self.assertEqual(1, head["version"])
            view2 = board.timeline_view(limit=10)
            self.assertEqual(2, view2["total"])
            self.assertIn("fetch", view2["head"]["text"])

    def test_workmem_goal_and_todo_deltas(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            board = SrcBlackboard(Path(tmp) / "bb.json")
            board.workmem_set(goal="挖 example.com")
            wm = board.workmem_apply_todos(
                [{"op": "add", "text": "复现 IDOR"}, {"op": "add", "text": "测 SQLi"}]
            )
            self.assertEqual(2, len(wm["todos"]))
            first_id = wm["todos"][0]["todo_id"]

            wm = board.workmem_apply_todos([{"op": "done", "todo_id": first_id}])
            done = next(t for t in wm["todos"] if t["todo_id"] == first_id)
            self.assertEqual("done", done["status"])

            wm = board.workmem_apply_todos([{"op": "drop", "todo_id": first_id}])
            self.assertEqual(1, len(wm["todos"]))
            self.assertEqual("挖 example.com", wm["goal"])

    def test_old_state_without_timeline_is_backward_compatible(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bb.json"
            path.write_text(
                json.dumps({
                    "schema": "SrcBlackboard/v1", "revision": 0, "updated_at": 1.0,
                    "facts": [], "intents": [], "dead_ends": [], "hints": [], "claims": [], "events": [],
                }),
                encoding="utf-8",
            )
            snapshot = SrcBlackboard(path).ensure()
            self.assertEqual([], snapshot["timeline"])
            self.assertIn("workmem", snapshot)
            self.assertEqual([], snapshot["workmem"]["todos"])


if __name__ == "__main__":
    unittest.main()
