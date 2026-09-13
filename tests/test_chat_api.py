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
from console.app import create_app  # noqa: E402
from agents import src_chat as agents_src_chat  # noqa: E402

PASSWORD = "strong-local-password"
SECRET = "session-secret-for-test-0123456789"


def _wait(cond, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(0.02)
    return False


class _ChatCase(unittest.TestCase):
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


class ChatApiTests(_ChatCase):
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
            f"/api/v1/chat/sessions/{session_id}/events").json()["max_seq"] >= 3))
        events = client.get(f"/api/v1/chat/sessions/{session_id}/events").json()["events"]
        kinds = [e["kind"] for e in events]
        # 1) the runner announces the subtask, 2/3) the turn's own events stream in
        self.assertEqual(["subtask_started", "user_message", "assistant_message"], kinds[:3])
        self.assertEqual([1, 2, 3], [e["seq"] for e in events][:3])
        # the announcement carries the job kind in its own field — the envelope
        # `kind` must stay "subtask_started" for the renderer to dispatch on
        self.assertEqual("chat_turn", events[0]["job_kind"])

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


class EscalationTests(_ChatCase):
    """The core mechanism: a turn in an action mode launches a real subtask.

    These run the *real* ``chat_turn`` handler so the intent-router →
    job-registry → event-log path is exercised end to end. Only the ``src_loop``
    handler is stubbed, so nothing touches the network.
    """

    SESSION = "src-esc1234567"

    def _client_with_stubbed_loop(self, seen: list):
        def fake_src_loop(job, ctx):
            seen.append(job.target)
            ctx.emit("subtask_progress", phase="recon")
            return {"summary_ref": "loop-done"}

        # Keep the model stubbed for the whole test, not just for start-up: the
        # turn job runs after this method returns, and an unstubbed `chat` would
        # make a real LLM call (slow, flaky, and it burns quota).
        patcher = patch.object(agents_src_chat, "chat", lambda session, text, **kw: "已收到")
        patcher.start()
        self.addCleanup(patcher.stop)
        return self.start_client({"src_loop": fake_src_loop})

    def test_target_plus_verb_launches_a_subtask_and_streams_it(self) -> None:
        seen: list = []
        client = self._client_with_stubbed_loop(seen)
        resp = client.post(f"/api/v1/chat/sessions/{self.SESSION}/messages",
                           json={"text": "扫描一下 http://example.com", "mode": "src_blackbox"})
        self.assertEqual(202, resp.status_code, resp.text)
        turn_job = resp.json()["job_id"]

        self.assertTrue(_wait(lambda: not console_jobs.active_jobs(self.state_dir)))
        self.assertEqual(["http://example.com"], seen)

        jobs = client.get(f"/api/v1/jobs?session_id={self.SESSION}").json()["jobs"]
        kinds = sorted(j["kind"] for j in jobs)
        self.assertEqual(["chat_turn", "src_loop"], kinds)
        loop = next(j for j in jobs if j["kind"] == "src_loop")
        self.assertEqual("completed", loop["status"])
        self.assertEqual("loop-done", loop["summary_ref"])
        self.assertEqual(turn_job, next(j for j in jobs if j["kind"] == "chat_turn")["job_id"])

        events = client.get(f"/api/v1/chat/sessions/{self.SESSION}/events").json()["events"]
        kinds = [e["kind"] for e in events]

        # the turn itself is announced first, then its own user message arrives
        self.assertEqual(["subtask_started", "user_message"], kinds[:2])
        started = [e for e in events if e["kind"] == "subtask_started"]
        self.assertEqual(["chat_turn", "src_loop"], [e["job_kind"] for e in started])
        # exactly one announcement per job: the runner owns it, the handler must
        # not emit a second copy
        self.assertEqual(2, len(started))

        announce = next(e for e in started if e["job_kind"] == "src_loop")
        # the envelope kind stays "subtask_started" so the renderer can dispatch
        self.assertEqual("src_loop", announce["job_kind"])
        self.assertEqual("http://example.com", announce["target"])
        # the announcement carries the mode's own title (core/modes.py), so a
        # rename there shows up here on purpose
        self.assertEqual("黑盒漏洞挖掘", announce["title"])
        self.assertEqual(loop["job_id"], announce["job_id"])
        # the subtask shares the turn's turn_id, so it renders inside that turn
        self.assertEqual(events[0]["turn_id"], announce["turn_id"])

        phases = [e["phase"] for e in events if e["kind"] == "subtask_progress"]
        self.assertIn("recon", phases)
        self.assertIn("assistant_message", kinds)
        # one terminal event per job, and both finished cleanly
        finished = [e for e in events if e["kind"] == "subtask_finished"]
        self.assertEqual(2, len(finished))
        self.assertEqual({"completed"}, {e["status"] for e in finished})

    def test_chat_mode_with_a_target_does_not_escalate(self) -> None:
        seen: list = []
        client = self._client_with_stubbed_loop(seen)
        resp = client.post(f"/api/v1/chat/sessions/{self.SESSION}/messages",
                           json={"text": "扫描一下 http://example.com", "mode": "chat"})
        self.assertEqual(202, resp.status_code, resp.text)
        self.assertTrue(_wait(lambda: not console_jobs.active_jobs(self.state_dir)))
        self.assertEqual([], seen)
        jobs = client.get(f"/api/v1/jobs?session_id={self.SESSION}").json()["jobs"]
        self.assertEqual(["chat_turn"], [j["kind"] for j in jobs])

    def test_mode_command_switches_the_mode_and_says_so(self) -> None:
        seen: list = []
        client = self._client_with_stubbed_loop(seen)
        client.post(f"/api/v1/chat/sessions/{self.SESSION}/messages",
                    json={"text": "进入 CTF 模式", "mode": "chat"})
        self.assertTrue(_wait(lambda: not console_jobs.active_jobs(self.state_dir)))
        events = client.get(f"/api/v1/chat/sessions/{self.SESSION}/events").json()["events"]
        changed = next(e for e in events if e["kind"] == "mode_changed")
        self.assertEqual("ctf", changed["mode"])
        # a mode switch alone must not launch anything
        self.assertEqual([], seen)


if __name__ == "__main__":
    unittest.main()
