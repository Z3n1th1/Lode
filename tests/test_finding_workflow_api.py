from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "core"))

from console.app import create_app  # noqa: E402
from core.finding_workflow import finding_id_for  # noqa: E402

PASSWORD = "strong-local-password"
SESSION_SECRET = "session-secret-for-test-0123456789"


class _Runner:
    def __init__(self) -> None:
        self.jobs = []

    def submit(self, job) -> None:
        self.jobs.append(job)


class FindingWorkflowApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.state = root / "state"
        self.output = root / "task-output"
        sarif_dir = self.output / "strix_runs" / "run-1"
        sarif_dir.mkdir(parents=True)
        self.finding_id = finding_id_for(task="T-1", rule="R-1", title="Query finding", target="https://example.test")
        scope = {
            "schema": "SrcRunScope/v1", "program": "example-program",
            "authorization": "written authorization", "allowed_hosts": ["example.test"],
            "allowed_domains": [], "forbidden": [], "allowed_methods": ["GET", "HEAD", "POST"],
            "allow_request_body": True, "requests_per_second": 2,
        }
        (self.output / "scope.json").write_text(json.dumps(scope), encoding="utf-8")
        sarif = {"version": "2.1.0", "runs": [{"results": [{
            "ruleId": "R-1", "message": {"text": "Query finding"},
            "properties": {
                "severity": "high", "summary": "Response marker observed",
                "evidence": "the original response contained owner_id",
                "request": {
                    "method": "POST", "url": "https://example.test/search",
                    "body": "{\"query\":\"record-1\"}", "content_type": "application/json",
                    "expected": {"status": 200, "markers": ["owner_id"]},
                },
            },
        }]}]}
        (sarif_dir / "findings.sarif").write_text(json.dumps(sarif), encoding="utf-8")
        (self.state / "strix_tasks.jsonl").parent.mkdir(parents=True, exist_ok=True)
        (self.state / "strix_tasks.jsonl").write_text(json.dumps({
            "id": "T-1", "output_path": str(self.output), "target": "https://example.test",
        }) + "\n", encoding="utf-8")
        static = root / "static"
        static.mkdir()
        (static / "index.html").write_text("<html></html>", encoding="utf-8")
        self.app = create_app(state_dir=self.state, password=PASSWORD,
                              session_secret=SESSION_SECRET, static_dir=static)
        self.client = TestClient(self.app)
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)
        self.assertEqual(204, self.client.post("/api/v1/session", json={"password": PASSWORD}).status_code)

    def test_detail_hides_raw_request_but_reports_safe_post_plan(self) -> None:
        response = self.client.get(f"/api/v1/findings/{self.finding_id}")
        self.assertEqual(200, response.status_code, response.text)
        body = response.json()
        self.assertNotIn("request", body["finding"])
        self.assertTrue(body["auto_retest_available"])
        self.assertIn("authorization", (self.output / "scope.json").read_text(encoding="utf-8"))

    def test_automatic_post_is_queued_through_the_job_runner_contract(self) -> None:
        runner = _Runner()
        with patch("console.jobs.get_runner", return_value=runner):
            response = self.client.post(f"/api/v1/findings/{self.finding_id}/retests", json={"mode": "automatic"})
        self.assertEqual(200, response.status_code, response.text)
        payload = response.json()
        self.assertTrue(payload["enqueued"])
        self.assertEqual(1, len(runner.jobs))
        self.assertEqual("finding_retest", runner.jobs[0].kind)
        self.assertEqual("POST", runner.jobs[0].payload["method"])
        self.assertEqual("https://example.test", runner.jobs[0].payload["target"])
        self.assertEqual("https://example.test/search", runner.jobs[0].payload["request_url"])

    def test_missing_original_scope_stays_manual_and_does_not_enqueue(self) -> None:
        output_two = Path(self.temp.name) / "task-output-two"
        sarif_two = output_two / "strix_runs" / "run-2"
        sarif_two.mkdir(parents=True)
        shutil.copyfile(self.output / "strix_runs" / "run-1" / "findings.sarif", sarif_two / "findings.sarif")
        with (self.state / "strix_tasks.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"id": "T-2", "output_path": str(output_two), "target": "https://example.test"}) + "\n")
        second_id = finding_id_for(task="T-2", rule="R-1", title="Query finding", target="https://example.test")
        detail = self.client.get(f"/api/v1/findings/{second_id}").json()
        self.assertFalse(detail["auto_retest_available"])
        runner = _Runner()
        with patch("console.jobs.get_runner", return_value=runner):
            response = self.client.post(f"/api/v1/findings/{second_id}/retests", json={"mode": "automatic"})
        body = response.json()
        self.assertFalse(body["enqueued"])
        self.assertEqual("pending_review", body["retest"]["status"])
        self.assertEqual([], runner.jobs)

    def test_batch_is_bounded_and_report_conflict_is_checked(self) -> None:
        runner = _Runner()
        with patch("console.jobs.get_runner", return_value=runner):
            batch = self.client.post("/api/v1/findings/retests/batch", json={
                "finding_ids": [self.finding_id] * 25,
            })
        self.assertEqual(200, batch.status_code, batch.text)
        self.assertEqual(1, len(batch.json()["results"]))
        detail = self.client.get(f"/api/v1/findings/{self.finding_id}").json()
        stale = self.client.post(f"/api/v1/findings/{self.finding_id}/report", json={
            "report": "# stale", "expected_digest": "0" * 64,
        })
        self.assertEqual(409, stale.status_code)
        saved = self.client.post(f"/api/v1/findings/{self.finding_id}/report", json={
            "report": detail["report_template"], "expected_digest": detail["evidence_digest"],
        })
        self.assertEqual(200, saved.status_code, saved.text)


if __name__ == "__main__":
    unittest.main()
