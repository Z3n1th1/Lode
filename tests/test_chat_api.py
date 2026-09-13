"""Tests for the unified /chat/* conversation endpoints.

The chat turn calls the LLM, so the ``chat_turn`` handler is replaced with a fake
— these cover the turn lifecycle and the inline event stream, not the model.
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
from console.control_plane import create_app  # noqa: E402

PASSWORD = "strong-local-password"
SECRET = "session-secret-for-test-0123456789"


def _wait(cond, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(0.02)
    return False


class ChatApiTests(unittest.TestCase):
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
        if handlers is None:
            client = TestClient(self.app)
            client.__enter__()
        else:
            with patch.dict(console_jobs.HANDLERS, handlers):
                client = TestClient(self.app)
                client.__enter__()   # lifespan builds the runner with the patched handlers
        self.addCleanup(client.__exit__, None, None, None)
        self.client = client
        self.assertEqual(204, client.post("/api/v1/session", json={"password": PASSWORD}).status_code)
        return client

    def test_modes_endpoint(self) -> None:
        client = self.start_client()
        body = client.get("/api/v1/modes").json()
        names = [m["name"] for m in body["modes"]]
        self.assertIn("ctf", names)
        self.assertEqual("chat", body["default"])

    def test_create_session_mints_an_id(self) -> None:
        client = self.start_client()
        body = client.post("/api/v1/chat/sessions", json={"mode": "ctf"}).json()
        self.assertTrue(body["session_id"].startswith("src-"))
        self.assertEqual("ctf", body["mode"])

    def test_turn_emits_events_inline(self) -> None:
        def fake_turn(job, ctx):
            ctx.emit("user_message", text="hi")
            ctx.emit("assistant_message", text="hello")
            return {"summary_ref": "session:x"}

        client = self.start_client({"chat_turn": fake_turn})
        session_id = "src-abc1234567"
        resp = client.post(f"/api/v1/chat/sessions/{session_id}/messages", json={"text": "hi"})
        self.assertEqual(202, resp.status_code, resp.text)
        turn = resp.json()
        self.assertTrue(turn["turn_id"].startswith("T-"))

        self.assertTrue(_wait(lambda: client.get(
            f"/api/v1/chat/sessions/{session_id}/events").json()["max_seq"] >= 2))
        events = client.get(f"/api/v1/chat/sessions/{session_id}/events").json()["events"]
        kinds = [e["kind"] for e in events]
        # the turn's own events come first; the runner then appends subtask_finished
        self.assertEqual(["user_message", "assistant_message"], kinds[:2])
        self.assertEqual([1, 2], [e["seq"] for e in events][:2])

        # the turn shows up as a completed job on the session
        jobs = client.get(f"/api/v1/jobs?session_id={session_id}").json()["jobs"]
        self.assertEqual("chat_turn", jobs[0]["kind"])
        self.assertTrue(_wait(lambda: client.get(f"/api/v1/jobs/{jobs[0]['job_id']}").json()["status"] == "completed"))

    def test_turn_rejects_empty_text(self) -> None:
        client = self.start_client({"chat_turn": lambda job, ctx: {}})
        resp = client.post("/api/v1/chat/sessions/src-abc1234567/messages", json={"text": "  "})
        self.assertEqual(400, resp.status_code)
        self.assertEqual("empty_message", resp.json()["detail"])

    def test_turn_rejects_bad_session_id(self) -> None:
        client = self.start_client({"chat_turn": lambda job, ctx: {}})
        resp = client.post("/api/v1/chat/sessions/src-" + "a" * 200 + "/messages", json={"text": "hi"})
        self.assertEqual(400, resp.status_code)

    def test_second_turn_conflicts_while_running(self) -> None:
        def slow(job, ctx):
            for _ in range(1000):
                if ctx.stopped():
                    return {}
                time.sleep(0.01)
            return {}

        client = self.start_client({"chat_turn": slow})
        session_id = "src-abc1234567"
        first = client.post(f"/api/v1/chat/sessions/{session_id}/messages", json={"text": "a"})
        self.assertEqual(202, first.status_code)
        second = client.post(f"/api/v1/chat/sessions/{session_id}/messages", json={"text": "b"})
        self.assertEqual(409, second.status_code)
        stop = client.post(f"/api/v1/chat/sessions/{session_id}/turn/stop")
        self.assertTrue(stop.json()["ok"])
        self.assertTrue(_wait(lambda: console_jobs.active_jobs(self.state_dir) == []))

    def test_stop_turn_when_idle(self) -> None:
        client = self.start_client({"chat_turn": lambda job, ctx: {}})
        resp = client.post("/api/v1/chat/sessions/src-abc1234567/turn/stop")
        self.assertEqual({"ok": False, "reason": "not_running"}, resp.json())

    def test_chat_endpoints_require_session(self) -> None:
        client = TestClient(self.app)
        client.__enter__()
        self.addCleanup(client.__exit__, None, None, None)
        self.assertEqual(401, client.get("/api/v1/modes").status_code)
        self.assertEqual(401, client.post("/api/v1/chat/sessions", json={}).status_code)
        self.assertEqual(401, client.post("/api/v1/chat/sessions/src-x1/messages", json={"text": "a"}).status_code)


if __name__ == "__main__":
    unittest.main()
