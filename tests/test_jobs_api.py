"""Tests for the durable job endpoints + the unified conversation stream.

The runner is built during app start-up (the lifespan calls recover()), so the
handler patch has to be active *before* TestClient enters the app.
"""
from __future__ import annotations

import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "core"))

from fastapi.testclient import TestClient  # noqa: E402

from console import jobs as console_jobs  # noqa: E402
from console.app import create_app  # noqa: E402

PASSWORD = "strong-local-password"
SECRET = "session-secret-for-test-0123456789"


def _wait(cond, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(0.02)
    return False


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.state_dir = root / "state"
        static = root / "static"
        (static / "assets").mkdir(parents=True)
        (static / "index.html").write_text("<html></html>", encoding="utf-8")
        self.app = create_app(state_dir=self.state_dir, password=PASSWORD,
                             session_secret=SECRET, static_dir=static)
        self.addCleanup(self._tmp.cleanup)
        self.addCleanup(console_jobs.shutdown_all)

    def start_client(self, handlers=None) -> TestClient:
        """Enter the app; ``handlers`` must be patched before start-up builds the runner."""
        if handlers is None:
            client = TestClient(self.app)
            client.__enter__()
        else:
            with patch.dict(console_jobs.HANDLERS, handlers):
                client = TestClient(self.app)
                client.__enter__()   # lifespan -> jobs.recover() -> builds the runner
        self.addCleanup(client.__exit__, None, None, None)
        self.client = client
        return client

    def login(self) -> None:
        self.assertEqual(204, self.client.post("/api/v1/session", json={"password": PASSWORD}).status_code)


class JobEndpointTests(_Base):
    """Job lifecycle. The only way to launch a durable job now is a chat turn."""

    SESSION = "src-abc1234567"

    def _send_turn(self, text="hi") -> dict:
        resp = self.client.post(f"/api/v1/chat/sessions/{self.SESSION}/messages", json={"text": text})
        self.assertEqual(202, resp.status_code, resp.text)
        return resp.json()

    def test_turn_creates_a_durable_job_and_completes(self) -> None:
        def fake_turn(job, ctx):
            ctx.progress(phase="done")
            return {"summary_ref": "sum-1"}

        self.start_client({"chat_turn": fake_turn})
        self.login()
        job_id = self._send_turn()["job_id"]
        self.assertTrue(job_id.startswith("J-"))

        listing = self.client.get("/api/v1/jobs").json()["jobs"]
        self.assertEqual([job_id], [j["job_id"] for j in listing])
        self.assertTrue(_wait(lambda: self.client.get(f"/api/v1/jobs/{job_id}").json()["status"] == "completed"))
        detail = self.client.get(f"/api/v1/jobs/{job_id}").json()
        self.assertEqual("chat_turn", detail["kind"])
        self.assertEqual(self.SESSION, detail["session_id"])
        self.assertEqual("sum-1", detail["summary_ref"])
        self.assertEqual("done", detail["progress"]["phase"])

    def test_job_stop_is_cooperative(self) -> None:
        def slow(job, ctx):
            for _ in range(1000):
                if ctx.stopped():
                    return {}
                time.sleep(0.01)
            return {}

        self.start_client({"chat_turn": slow})
        self.login()
        job_id = self._send_turn()["job_id"]
        stop = self.client.post(f"/api/v1/jobs/{job_id}/stop")
        self.assertEqual(200, stop.status_code, stop.text)
        self.assertTrue(_wait(lambda: self.client.get(f"/api/v1/jobs/{job_id}").json()["status"]
                              in {"failed", "completed", "interrupted"}))

    def test_stop_turn_when_idle(self) -> None:
        self.start_client()
        self.login()
        resp = self.client.post(f"/api/v1/chat/sessions/{self.SESSION}/turn/stop")
        self.assertEqual({"ok": False, "reason": "not_running"}, resp.json())

    def test_jobs_require_session(self) -> None:
        self.start_client()
        self.assertEqual(401, self.client.get("/api/v1/jobs").status_code)
        self.assertEqual(401, self.client.get("/api/v1/jobs/J-x").status_code)
        self.assertEqual(401, self.client.post("/api/v1/jobs/J-x/stop").status_code)

    def test_job_get_unknown_is_404(self) -> None:
        self.start_client()
        self.login()
        self.assertEqual(404, self.client.get("/api/v1/jobs/J-nope").status_code)
        self.assertEqual(404, self.client.post("/api/v1/jobs/J-nope/stop").status_code)


class ChatStreamTests(_Base):
    def test_stream_requires_session(self) -> None:
        self.start_client()
        self.assertEqual(401, self.client.get("/api/v1/chat/sessions/src-abc123/stream").status_code)

    def test_stream_rejects_bad_session_id(self) -> None:
        self.start_client()
        self.login()
        resp = self.client.get("/api/v1/chat/sessions/..%2fetc/stream")
        self.assertIn(resp.status_code, (400, 404))


if __name__ == "__main__":
    unittest.main()
