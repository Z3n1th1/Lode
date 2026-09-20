from __future__ import annotations

import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import List

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


class SrcBlackboardTemporalFactTests(unittest.TestCase):
    """graphiti-style: facts carry a validity window; dead-ends invalidate, not delete."""

    def test_sync_creates_episode_and_facts_are_temporal(self) -> None:
        clock = [1000.0]
        with tempfile.TemporaryDirectory() as tmp:
            board = SrcBlackboard(Path(tmp) / "bb.json", now_fn=lambda: clock[0])
            board.sync_candidates(
                [{"candidate_id": "SC-X", "url": "https://ex.com/x", "priority": 50}],
                run_id="r1",
            )
            snap = board.snapshot()
            fact = snap["facts"][0]
            self.assertEqual(1000.0, fact["valid_from"])
            self.assertIsNone(fact["valid_to"])
            self.assertTrue(fact["episode_id"])
            # the observation batch is recorded as a timeline episode
            self.assertTrue(
                any(i.get("item_id") == fact["episode_id"] and i.get("kind") == "episode"
                    for i in snap["timeline"])
            )

    def test_dead_end_supersedes_fact_but_keeps_history(self) -> None:
        clock = [1000.0]
        with tempfile.TemporaryDirectory() as tmp:
            board = SrcBlackboard(Path(tmp) / "bb.json", now_fn=lambda: clock[0])
            board.sync_candidates(
                [{"candidate_id": "SC-Y", "url": "https://ex.com/y", "priority": 50}],
                run_id="r2",
            )
            fact_id = board.snapshot()["facts"][0]["fact_id"]
            intent_id = board.snapshot()["intents"][0]["intent_id"]

            clock[0] = 1005.0
            claim = board.claim_next("w1")
            board.add_dead_end(intent_id, "no_finding")

            fact = board.snapshot()["facts"][0]
            self.assertEqual(1005.0, fact["valid_to"])
            self.assertEqual("no_finding", fact["superseded_reason"])
            # valid at t=1002, invalid at t=1010
            self.assertIn(fact_id, [f["fact_id"] for f in board.facts_as_of(1002.0)])
            self.assertNotIn(fact_id, [f["fact_id"] for f in board.facts_as_of(1010.0)])


class SrcBlackboardRecallTests(unittest.TestCase):
    """memory retrieval: reuse valid *and* superseded facts + dead-ends from history."""

    def _seed(self, board: SrcBlackboard) -> List[str]:
        board.sync_candidates(
            [
                {"candidate_id": "SC-A", "url": "https://example.com/api/users", "priority": 90},
                {"candidate_id": "SC-B", "url": "https://other.test/x", "priority": 50},
            ],
            run_id="r1",
        )
        return [item["intent_id"] for item in board.snapshot()["intents"]]

    def test_recall_returns_historical_fact_and_dead_end(self) -> None:
        clock = [1000.0]
        with tempfile.TemporaryDirectory() as tmp:
            board = SrcBlackboard(Path(tmp) / "bb.json", now_fn=lambda: clock[0])
            first, _second = self._seed(board)
            board.claim_next("w1")  # claims the 90-priority SC-A
            clock[0] = 1005.0
            board.add_dead_end(first, "no_finding_on_users")

            results = board.recall(["https://example.com/api/users"], limit=1, per_query=3)
            self.assertEqual(1, len(results))
            fact = results[0]["facts"][0]
            self.assertEqual("https://example.com/api/users", fact["url"])
            self.assertFalse(fact["valid"])  # superseded by the dead-end
            self.assertEqual("no_finding_on_users", fact["superseded_reason"])
            self.assertIn("no_finding_on_users", [d["reason"] for d in results[0]["dead_ends"]])

    def test_recall_ignores_unrelated_hosts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            board = SrcBlackboard(Path(tmp) / "bb.json")
            self._seed(board)
            results = board.recall(["https://example.com/api/users"], limit=1, per_query=3)
            self.assertTrue(all("other.test" not in f["url"] for f in results[0]["facts"]))

    def test_recall_matches_same_host_different_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            board = SrcBlackboard(Path(tmp) / "bb.json")
            self._seed(board)
            results = board.recall(["https://example.com/api/orders"], limit=1, per_query=3)
            self.assertIn(
                "https://example.com/api/users",
                [f["url"] for f in results[0]["facts"]],
            )

    def test_recall_empty_query_returns_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            board = SrcBlackboard(Path(tmp) / "bb.json")
            self._seed(board)
            self.assertEqual([], board.recall([]))
            self.assertEqual([], board.recall("   "))


class SrcBlackboardDagClaimTests(unittest.TestCase):
    """reasoner-driven DAG: targeted claims honour deps; unsafe edges are dropped."""

    def _seed(self, board: SrcBlackboard) -> List[str]:
        board.sync_candidates(
            [
                {"candidate_id": "SC-A", "url": "https://example.com/a", "priority": 90},
                {"candidate_id": "SC-B", "url": "https://example.com/b", "priority": 80},
            ],
            run_id="r",
        )
        return [item["intent_id"] for item in board.snapshot()["intents"]]

    def test_claim_intent_targets_the_exact_intent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            board = SrcBlackboard(Path(tmp) / "bb.json", default_lease_seconds=60)
            _first, second = self._seed(board)
            claim = board.claim_intent(second, "w1")
            self.assertIsNotNone(claim)
            self.assertEqual(second, claim["intent"]["intent_id"])
            self.assertIsNone(board.claim_intent(second, "w2"))  # already claimed

    def test_claim_intent_waits_for_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            board = SrcBlackboard(Path(tmp) / "bb.json", default_lease_seconds=60)
            first, second = self._seed(board)
            board.set_dependencies(second, [first])

            self.assertIsNone(board.claim_intent(second, "w1"))  # blocker unmet
            self.assertIsNotNone(board.claim_intent(first, "w1"))
            board.finish(first, "w1", status="completed")
            self.assertIsNotNone(board.claim_intent(second, "w2"))

    def test_set_dependencies_drops_unknown_self_and_cyclic_edges(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            board = SrcBlackboard(Path(tmp) / "bb.json", default_lease_seconds=60)
            first, second = self._seed(board)
            self.assertEqual([], board.set_dependencies(first, ["I-ghost"])["depends_on"])
            self.assertEqual([], board.set_dependencies(first, [first])["depends_on"])
            self.assertEqual([second], board.set_dependencies(first, [second])["depends_on"])
            # second -> first would close a cycle (first -> second), so it is dropped.
            self.assertEqual([], board.set_dependencies(second, [first])["depends_on"])


    def test_snapshot_trims_intents_from_the_top_not_the_bottom(self) -> None:
        """intents 是**按优先级降序**存的,所以裁剪的必须是尾部。

        以前 ``_bounded_list`` 对每一张表都取 ``[-limit:]``:对只追加的 facts/
        hints/events 是对的,对 intents 就是把最能干的 2000 个丢掉、留下最差的
        2000 个。上限调小来测,是为了让这条断言真的跑到那条分支上。
        """
        from unittest import mock

        from core import src_blackboard as bb_module

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bb.json"
            state = {
                "schema": "SrcBlackboard/v1", "revision": 0, "updated_at": 0.0,
                "facts": [{"fact_id": f"F-{i}"} for i in range(10)],
                "intents": [{"intent_id": f"I-{i}", "priority": 100 - i} for i in range(10)],
                "dead_ends": [], "hints": [], "claims": [], "events": [], "timeline": [],
            }
            path.write_text(json.dumps(state), encoding="utf-8")
            board = SrcBlackboard(path, default_lease_seconds=60)
            board.ensure()          # snapshot() 不加锁创建,所以先让锁的 sidecar 存在
            with mock.patch.object(bb_module, "MAX_ITEMS", 3):
                snapshot = board.snapshot()

        self.assertEqual(["I-0", "I-1", "I-2"], [row["intent_id"] for row in snapshot["intents"]])
        # facts 是插入序,取尾部 = 最近的三条(别跟着 intents 一起改)
        self.assertEqual(["F-7", "F-8", "F-9"], [row["fact_id"] for row in snapshot["facts"]])


if __name__ == "__main__":
    unittest.main()
