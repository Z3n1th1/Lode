from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path

from core.finding_workflow import (
    FindingRetestStore, finding_id_for, report_template, requires_human_review,
    retest_instruction,
)


class FindingWorkflowTests(unittest.TestCase):
    def finding(self) -> dict:
        return {
            "finding_id": finding_id_for(task="T-1", rule="idor", title="跨用户读取", target="https://example.com/Api"),
            "task": "T-1", "rule": "idor", "severity": "high", "title": "跨用户读取",
            "target": "https://example.com/Api", "evidence": {"response": "A/B response difference"},
            "requests": [{"method": "POST", "path": "/Api/query", "operation": "read"}],
            "scope_ref": "scope.json",
        }

    def test_identity_preserves_case_and_review_is_explicit(self) -> None:
        value = self.finding()
        self.assertNotEqual(value["finding_id"], finding_id_for(
            task="T-1", rule="idor", title="跨用户读取", target="https://example.com/api"))
        self.assertFalse(requires_human_review(value))
        value["review_reason"] = "unknown route semantics"
        self.assertTrue(requires_human_review(value))
        self.assertIn("只读 POST", retest_instruction(value))
        self.assertIn("删除", retest_instruction(value))

    def test_report_contains_facts_and_escapes_untrusted_markdown(self) -> None:
        value = self.finding()
        value["title"] = "<script>alert(1)</script> # x"
        value["evidence"] = "```\n<script>\n```"
        rendered = report_template(value, retests=[{
            "retest_id": "RT-test", "status": "completed", "verdict": "inconclusive",
            "source": "manual", "summary": "条件不符", "evidence": "401", "result_at": 1,
        }])
        self.assertIn("&lt;script&gt;", rendered)
        self.assertNotIn("```", rendered)
        self.assertIn("人工记录", rendered)
        self.assertIn("条件不符", rendered)
        self.assertIn("未记录", rendered)
        self.assertIn("## 复测记录", rendered)

    def test_retest_dedup_snapshot_immutable_and_atomic_completion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = FindingRetestStore(Path(tmp) / "finding-retests.jsonl")
            finding = self.finding()
            first, created = store.create(finding, notes="只验证原始对象边界")
            self.assertTrue(created)
            self.assertEqual("recorded", first["status"])
            finding["evidence"]["response"] = "tampered"
            first["finding_snapshot"]["evidence"]["response"] = "caller mutation"
            second, created_again = store.create(self.finding(), notes="重复点击")
            self.assertFalse(created_again)
            self.assertEqual(first["retest_id"], second["retest_id"])
            self.assertEqual("A/B response difference", second["finding_snapshot"]["evidence"]["response"])
            self.assertEqual("read", second["finding_snapshot"]["requests"][0]["operation"])
            self.assertEqual("scope.json", second["finding_snapshot"]["scope_ref"])
            result = store.record_result(first["retest_id"], verdict="inconclusive",
                                         summary="测试账号不可用", evidence="401 与原始条件不一致")
            self.assertEqual("completed", result["status"])
            self.assertEqual("manual", result["source"])
            self.assertEqual(result, store.record_result(first["retest_id"], verdict="inconclusive",
                                                         summary="测试账号不可用", evidence="401 与原始条件不一致"))
            with self.assertRaisesRegex(ValueError, "invalid_retest_transition"):
                store.set_status(first["retest_id"], "running")
            with self.assertRaisesRegex(ValueError, "retest_not_active"):
                store.record_result(first["retest_id"], verdict="reproduced", summary="different", evidence="different")
            events = [json.loads(line) for line in store.path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(["created", "completed"], [event["event"] for event in events])
            fresh, created = store.create(self.finding())
            self.assertTrue(created)
            self.assertNotEqual(first["retest_id"], fresh["retest_id"])

    def test_job_binding_and_status_transitions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = FindingRetestStore(Path(tmp) / "finding-retests.jsonl")
            record, _ = store.create(self.finding())
            with self.assertRaisesRegex(ValueError, "automatic_retest_not_bound"):
                store.record_result(record["retest_id"], source="automatic", verdict="reproduced",
                                    summary="still present", evidence="response ref")
            bound = store.bind_job(record["retest_id"], "JOB-1", "T-1")
            self.assertEqual("queued", bound["status"])
            self.assertEqual("JOB-1", store.get(record["retest_id"])["job_id"])
            self.assertEqual(bound, store.bind_job(record["retest_id"], "JOB-1", "T-1"))
            store.set_status(record["retest_id"], "running")
            completed = store.record_result(record["retest_id"], source="automatic", verdict="reproduced",
                                            summary="still present", evidence="response ref")
            self.assertEqual("automatic", completed["source"])
            with self.assertRaisesRegex(ValueError, "invalid_retest_status"):
                store.set_status(record["retest_id"], "completed")

    def test_explicit_review_blocks_job_binding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = FindingRetestStore(Path(tmp) / "finding-retests.jsonl")
            record, _ = store.create(self.finding(), review_reason="unknown write side effect")
            self.assertEqual("pending_review", record["status"])
            with self.assertRaisesRegex(ValueError, "retest_not_bindable"):
                store.bind_job(record["retest_id"], "JOB-1", "T-1")
            store.set_status(record["retest_id"], "recorded")
            self.assertEqual("queued", store.bind_job(record["retest_id"], "JOB-1", "T-1")["status"])

    def test_fixed_needs_three_distinct_existing_evidence_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = FindingRetestStore(root / "finding-retests.jsonl")
            record, _ = store.create(self.finding())
            with self.assertRaisesRegex(ValueError, "fixed_evidence_incomplete"):
                store.record_result(record["retest_id"], verdict="fixed", summary="looks fixed",
                                    evidence="original current control")
            names = ("original.txt", "current.txt", "control.txt")
            for name in names:
                (root / name).write_text(name, encoding="utf-8")
            checks = {kind: {"reference": name, "outcome": outcome}
                      for kind, name, outcome in zip(("original", "current", "control"), names,
                                                     ("reproduced", "not_reproduced", "passed"))}
            result = store.record_result(record["retest_id"], verdict="fixed", summary="three-way comparison",
                                         evidence="see referenced artifacts", checks=checks)
            self.assertEqual("fixed", result["verdict"])
            self.assertEqual(64, len(result["checks"]["original"]["sha256"]))
            self.assertIn("original.txt", report_template(self.finding(), retests=[result]))

    def test_corrupt_log_and_bounded_input_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = FindingRetestStore(Path(tmp) / "finding-retests.jsonl")
            with self.assertRaisesRegex(ValueError, "notes_too_long"):
                store.create(self.finding(), notes="x" * 4001)
            store.path.write_text("{bad}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "retest_log_malformed"):
                store.create(self.finding())

    def test_concurrent_create_only_one_active(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = FindingRetestStore(Path(tmp) / "finding-retests.jsonl")
            results: list[tuple[dict, bool]] = []
            workers = [threading.Thread(target=lambda: results.append(store.create(self.finding()))) for _ in range(8)]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join()
            self.assertEqual(8, len(results))
            self.assertEqual(1, sum(created for _, created in results))
            self.assertEqual(1, len({row["retest_id"] for row, _ in results}))


if __name__ == "__main__":
    unittest.main()
