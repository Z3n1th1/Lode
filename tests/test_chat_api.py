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
from core import intent_router  # noqa: E402

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
        # 兜底分类器现在真的会走 LLM(以前这条路是死代码)。测试一律短路:一个
        # 用例想验证兜底行为就自己覆盖它,别的用例绝不允许碰网络。
        llm = patch.object(agents_src_chat, "_default_llm_complete", lambda *a, **k: None)
        llm.start()
        self.addCleanup(llm.stop)

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
        # one action mode: black-box hunting and authorized pentest share it
        self.assertEqual(["chat", "pentest"], names)
        self.assertEqual("chat", body["default"])

    def test_create_session_mints_an_id(self) -> None:
        client = self.start_client()
        body = client.post("/api/v1/chat/sessions", json={"mode": "pentest"}).json()
        self.assertTrue(body["session_id"].startswith("src-"))
        self.assertEqual("pentest", body["mode"])

    def test_events_report_a_job_that_is_still_running(self) -> None:
        """attach 到一条已经在跑的会话时,前端靠 active_jobs 认出"这一轮不是我发的、
        而且不能往里发" —— 不然用户打完字才撞一个 409 turn_already_running。"""
        client = self.start_client()
        session_id = "src-abc1234567"

        idle = client.get(f"/api/v1/chat/sessions/{session_id}/events").json()
        self.assertEqual([], idle["active_jobs"])

        # queued 也算 active,所以造一个 job 就够,不必真的起 runner。
        console_jobs.get_registry(self.state_dir).create(
            session_id=session_id, turn_id="T-run", kind="target_run",
            target="https://run.example.test", payload={},
        )

        busy = client.get(f"/api/v1/chat/sessions/{session_id}/events").json()
        self.assertEqual(["target_run"], [job["kind"] for job in busy["active_jobs"]])
        self.assertEqual("https://run.example.test", busy["active_jobs"][0]["target"])

        # 别的会话不该被牵连。
        other = client.get("/api/v1/chat/sessions/src-ffffffffff/events").json()
        self.assertEqual([], other["active_jobs"])

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
                           json={"text": "扫描一下 http://example.com", "mode": "pentest"})
        self.assertEqual(202, resp.status_code, resp.text)
        turn_job = resp.json()["job_id"]

        self.assertTrue(_wait(lambda: not console_jobs.active_jobs(self.state_dir)))
        self.assertEqual(["http://example.com/"], seen)

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
        self.assertEqual("http://example.com/", announce["target"])
        # the announcement carries the mode's own title (core/modes.py), so a
        # rename there shows up here on purpose
        self.assertEqual("挖洞", announce["title"])
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

    def test_a_pasted_list_fans_out_to_one_job_per_asset(self) -> None:
        """一份清单是一批资产:每个资产自己一个任务。

        一个任务扫整份清单会把每个资产的授权范围放宽到全清单,所以按资产切开。
        它们共用这一轮的 ``turn_id``,因此渲染在这一轮里,一个停止就能全停。
        """
        seen: list = []
        client = self._client_with_stubbed_loop(seen)
        resp = client.post(f"/api/v1/chat/sessions/{self.SESSION}/messages",
                           json={"text": "扫描一下 https://a.example.com https://b.example.com c.example.com",
                                 "mode": "pentest"})
        self.assertEqual(202, resp.status_code, resp.text)
        self.assertTrue(_wait(lambda: not console_jobs.active_jobs(self.state_dir)))

        expected = ["https://a.example.com/", "https://b.example.com/", "https://c.example.com/"]
        self.assertEqual(expected, sorted(seen))

        jobs = client.get(f"/api/v1/jobs?session_id={self.SESSION}").json()["jobs"]
        loops = [j for j in jobs if j["kind"] == "src_loop"]
        self.assertEqual(3, len(loops))
        # 三个任务,三个不同的目标 —— 不是一个目标起三遍
        self.assertEqual(expected, sorted(j["target"] for j in loops))
        self.assertEqual({"completed"}, {j["status"] for j in loops})
        turn_id = next(j for j in jobs if j["kind"] == "chat_turn")["turn_id"]
        self.assertEqual({turn_id}, {j["turn_id"] for j in loops})

        # 每个任务各自的 subtask_started,标题来自 mode(挖洞)
        started = [e for e in client.get(f"/api/v1/chat/sessions/{self.SESSION}/events").json()["events"]
                   if e["kind"] == "subtask_started" and e["job_kind"] == "src_loop"]
        self.assertEqual(3, len(started))
        self.assertEqual(expected, sorted(e["target"] for e in started))

    def test_a_list_longer_than_the_fan_out_cap_says_what_it_dropped(self) -> None:
        """池子只有两个 worker,排到队列尾部的等于挂着一堆不会动的行。

        超出上限的部分在对话里点名,不静默丢。
        """
        seen: list = []
        client = self._client_with_stubbed_loop(seen)
        text = "扫描一下 " + " ".join(f"https://h{i}.example.com" for i in range(5))
        with patch.object(console_jobs, "MAX_FANOUT", 2):
            resp = client.post(f"/api/v1/chat/sessions/{self.SESSION}/messages",
                               json={"text": text, "mode": "pentest"})
            self.assertEqual(202, resp.status_code, resp.text)
            self.assertTrue(_wait(lambda: not console_jobs.active_jobs(self.state_dir)))

        self.assertEqual(2, len(seen))
        jobs = client.get(f"/api/v1/jobs?session_id={self.SESSION}").json()["jobs"]
        self.assertEqual(2, len([j for j in jobs if j["kind"] == "src_loop"]))
        events = client.get(f"/api/v1/chat/sessions/{self.SESSION}/events").json()["events"]
        reply = next(e for e in events if e["kind"] == "assistant_message")["text"]
        self.assertIn("起了 2 个", reply)
        self.assertIn("3 个超出本轮 2 个的上限", reply)

    def test_a_non_public_seed_never_becomes_a_job(self) -> None:
        """分类器给的目标没走过 targets.py 的闸门,所以建 job 前要再拦一次。

        过了这一步目标就是持久化记录,并且真的会发请求 —— 私网地址不该走到那里。
        清单里识别到的公网目标照起,被拦下的在对话里点名。
        """
        seen: list = []
        client = self._client_with_stubbed_loop(seen)
        decided = intent_router.RouteDecision(
            action=intent_router.ESCALATE, subtask_kind="src_loop", mode="pentest", reason="llm",
            target="http://127.0.0.1:8080/admin",
            targets=["http://127.0.0.1:8080/admin", "https://ok.example.com/"])
        with patch.object(intent_router, "route", return_value=decided):
            resp = client.post(f"/api/v1/chat/sessions/{self.SESSION}/messages",
                               json={"text": "看看这两个", "mode": "pentest"})
            self.assertEqual(202, resp.status_code, resp.text)
            self.assertTrue(_wait(lambda: not console_jobs.active_jobs(self.state_dir)))

        self.assertEqual(["https://ok.example.com/"], seen)
        jobs = client.get(f"/api/v1/jobs?session_id={self.SESSION}").json()["jobs"]
        self.assertEqual(["https://ok.example.com/"],
                         [j["target"] for j in jobs if j["kind"] == "src_loop"])
        events = client.get(f"/api/v1/chat/sessions/{self.SESSION}/events").json()["events"]
        reply = next(e for e in events if e["kind"] == "assistant_message")["text"]
        self.assertIn("1 个不是公网 http(s)", reply)

    def test_a_route_without_targets_still_launches_its_one_target(self) -> None:
        """分类器只回一个 ``target``(没有 ``targets``),不能就一个任务都不起。"""
        seen: list = []
        client = self._client_with_stubbed_loop(seen)
        decided = intent_router.RouteDecision(
            action=intent_router.ESCALATE, subtask_kind="src_loop",
            target="https://solo.example.com/", mode="pentest", reason="llm")
        with patch.object(intent_router, "route", return_value=decided):
            resp = client.post(f"/api/v1/chat/sessions/{self.SESSION}/messages",
                               json={"text": "看看 https://solo.example.com/", "mode": "pentest"})
            self.assertEqual(202, resp.status_code, resp.text)
            self.assertTrue(_wait(lambda: not console_jobs.active_jobs(self.state_dir)))

        self.assertEqual(["https://solo.example.com/"], seen)

    def test_a_terse_verb_launches_without_asking_the_classifier(self) -> None:
        """一句"扫 x.com y.com"要直接开跑,不该先花一次分类调用。"""
        seen: list = []
        asked: list = []
        client = self._client_with_stubbed_loop(seen)
        with patch.object(agents_src_chat, "_default_llm_complete",
                          lambda system, user, **kw: asked.append(user) or None):
            resp = client.post(f"/api/v1/chat/sessions/{self.SESSION}/messages",
                               json={"text": "扫 https://a.example.com https://b.example.com",
                                     "mode": "pentest"})
            self.assertEqual(202, resp.status_code, resp.text)
            self.assertTrue(_wait(lambda: not console_jobs.active_jobs(self.state_dir)))

        self.assertEqual([], asked)
        self.assertEqual(["https://a.example.com/", "https://b.example.com/"], sorted(seen))

    def test_the_chat_path_hands_the_classifier_to_the_router(self) -> None:
        """兜底分类器必须真的接上:``route`` 拿不到这个回调时就只剩规则,

        而规则读不懂的说法(这里是"看看…能不能打")就永远是"只回话"。以前这条线
        在 ``_handler_chat_turn`` 里没接线,整段兜底是死代码。
        """
        seen: list = []
        client = self._client_with_stubbed_loop(seen)

        def fake_complete(system, user, **kwargs):
            self.assertIn("route user intent", system)
            return '{"action":"escalate","subtask_kind":"src_loop","reason":"ask"}'

        with patch.object(agents_src_chat, "_default_llm_complete", fake_complete):
            resp = client.post(f"/api/v1/chat/sessions/{self.SESSION}/messages",
                               json={"text": "看看 https://solo.example.com/ 能不能打",
                                     "mode": "pentest"})
            self.assertEqual(202, resp.status_code, resp.text)
            self.assertTrue(_wait(lambda: not console_jobs.active_jobs(self.state_dir)))

        self.assertEqual(["https://solo.example.com/"], seen)

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

    def test_an_invented_subtask_kind_does_not_launch_a_job(self) -> None:
        """The subtask kind can come from the classifier's own JSON, so it is untrusted.

        A kind with no executor would mint a job that always fails
        ``no_handler:<kind>`` — a red row for a capability that does not exist. The
        turn says so in the conversation instead of launching it.
        """
        seen: list = []
        client = self._client_with_stubbed_loop(seen)
        invented = intent_router.RouteDecision(
            action=intent_router.ESCALATE, subtask_kind="recon", target="http://example.com",
            mode="pentest", reason="llm")
        with patch.object(intent_router, "route", return_value=invented):
            resp = client.post(f"/api/v1/chat/sessions/{self.SESSION}/messages",
                               json={"text": "看看 http://example.com", "mode": "pentest"})
            self.assertEqual(202, resp.status_code, resp.text)
            self.assertTrue(_wait(lambda: not console_jobs.active_jobs(self.state_dir)))

        self.assertEqual([], seen)
        jobs = client.get(f"/api/v1/jobs?session_id={self.SESSION}").json()["jobs"]
        self.assertEqual(["chat_turn"], [j["kind"] for j in jobs])

        events = client.get(f"/api/v1/chat/sessions/{self.SESSION}/events").json()["events"]
        reply = next(e for e in events if e["kind"] == "assistant_message")["text"]
        self.assertIn("recon", reply)
        self.assertIn("已收到", reply)
        # nothing was announced: no subtask_started beyond the turn job itself
        started = [e for e in events if e["kind"] == "subtask_started"]
        self.assertEqual(["chat_turn"], [e["job_kind"] for e in started])

    def test_the_hunting_turn_offers_the_modes_own_tools(self) -> None:
        """The real turn must advertise ``mode.tools``, resolved to real schemas.

        Everything else here stubs ``chat``; this one runs it, with only the LLM
        completion seam faked, so it pins the mode -> registry -> tool-loop wiring.
        """
        captured: dict = {}

        def fake_src_loop(job, ctx):
            return {"summary_ref": "loop-done"}

        def fake_complete(messages, *, tools=None, timeout=90.0):
            captured["tools"] = [s["function"]["name"] for s in (tools or [])]
            return {"content": "已收到", "tool_calls": []}

        patcher = patch.object(agents_src_chat, "_llm_call", fake_complete)
        patcher.start()
        self.addCleanup(patcher.stop)
        client = self.start_client({"src_loop": fake_src_loop})

        resp = client.post(f"/api/v1/chat/sessions/{self.SESSION}/messages",
                           json={"text": "先说下思路", "mode": "pentest"})
        self.assertEqual(202, resp.status_code, resp.text)
        self.assertTrue(_wait(lambda: not console_jobs.active_jobs(self.state_dir)))
        self.assertEqual(["scan_target", "run_agent_analysis", "fetch_url", "show_blackboard",
                          "add_candidates", "show_progress", "auto_scan", "read_knowledge"],
                         captured["tools"])

    def test_chat_mode_turn_offers_no_tools(self) -> None:
        """A declared-empty tool list means nothing is advertised, not the hunting set."""
        captured: dict = {}

        def fake_complete(messages, *, tools=None, timeout=90.0):
            captured["tools"] = tools
            return {"content": "已收到", "tool_calls": []}

        patcher = patch.object(agents_src_chat, "_llm_call", fake_complete)
        patcher.start()
        self.addCleanup(patcher.stop)
        client = self.start_client({"src_loop": lambda job, ctx: {}})

        resp = client.post(f"/api/v1/chat/sessions/{self.SESSION}/messages",
                           json={"text": "只聊聊", "mode": "chat"})
        self.assertEqual(202, resp.status_code, resp.text)
        self.assertTrue(_wait(lambda: not console_jobs.active_jobs(self.state_dir)))
        self.assertEqual([], captured["tools"])

    def test_mode_command_switches_the_mode_and_says_so(self) -> None:
        seen: list = []
        client = self._client_with_stubbed_loop(seen)
        client.post(f"/api/v1/chat/sessions/{self.SESSION}/messages",
                    json={"text": "进入挖洞模式", "mode": "chat"})
        self.assertTrue(_wait(lambda: not console_jobs.active_jobs(self.state_dir)))
        events = client.get(f"/api/v1/chat/sessions/{self.SESSION}/events").json()["events"]
        changed = next(e for e in events if e["kind"] == "mode_changed")
        self.assertEqual("pentest", changed["mode"])
        # a mode switch alone must not launch anything
        self.assertEqual([], seen)

    def test_asking_for_surface_only_creates_a_surface_scan_job(self) -> None:
        """建面要真能从对话里发起。

        ``surface_scan`` 有 handler、UI 也把它渲染成「攻击面侦察」,但全仓 grep
        不到生产者 —— 说是能只建面,其实只会起 src_loop,把整个 LLM 循环烧在一个
        只想先看一眼的站上。
        """
        seen: list = []

        def fake_surface(job, ctx):
            seen.append(job.target)
            ctx.emit("subtask_progress", phase="done")
            return {"summary_ref": "surface-done"}

        patcher = patch.object(agents_src_chat, "chat", lambda session, text, **kw: "已收到")
        patcher.start()
        self.addCleanup(patcher.stop)
        client = self.start_client({"surface_scan": fake_surface})

        resp = client.post(f"/api/v1/chat/sessions/{self.SESSION}/messages",
                           json={"text": "只建面 扫 a.example.com", "mode": "pentest"})
        self.assertEqual(202, resp.status_code, resp.text)
        self.assertTrue(_wait(lambda: not console_jobs.active_jobs(self.state_dir)))
        self.assertEqual(["https://a.example.com/"], seen)

        jobs = client.get(f"/api/v1/jobs?session_id={self.SESSION}").json()["jobs"]
        self.assertIn("surface_scan", [j["kind"] for j in jobs])
        self.assertNotIn("src_loop", [j["kind"] for j in jobs])

    def test_a_bare_mode_command_switches_and_launches_in_one_turn(self) -> None:
        """「改成挖洞,扫 x」一句话就该切模式 + 开跑,不用先发一句再发清单。"""
        seen: list = []
        client = self._client_with_stubbed_loop(seen)
        client.post(f"/api/v1/chat/sessions/{self.SESSION}/messages",
                    json={"text": "改成挖洞 扫 a.example.com", "mode": "chat"})
        self.assertTrue(_wait(lambda: not console_jobs.active_jobs(self.state_dir)))
        self.assertEqual(["https://a.example.com/"], seen)

        events = client.get(f"/api/v1/chat/sessions/{self.SESSION}/events").json()["events"]
        changed = next(e for e in events if e["kind"] == "mode_changed")
        self.assertEqual("pentest", changed["mode"])
        # 子任务的标题来自换过之后的模式,不是发起时那个
        announce = next(e for e in events if e["kind"] == "subtask_started"
                        and e["job_kind"] == "src_loop")
        self.assertEqual("挖洞", announce["title"])

    def test_chat_mode_names_the_way_out_instead_of_silently_replying(self) -> None:
        """对话模式下说出了「目标 + 动作词」却没开跑,回复里必须说明怎么切。"""
        seen: list = []
        client = self._client_with_stubbed_loop(seen)
        client.post(f"/api/v1/chat/sessions/{self.SESSION}/messages",
                    json={"text": "扫描一下 https://example.com", "mode": "chat"})
        self.assertTrue(_wait(lambda: not console_jobs.active_jobs(self.state_dir)))
        self.assertEqual([], seen)

        events = client.get(f"/api/v1/chat/sessions/{self.SESSION}/events").json()["events"]
        reply = next(e for e in events if e["kind"] == "assistant_message")
        self.assertIn("挖洞", reply["text"])
        # 只是提示怎么切,不是偷偷换了模式
        self.assertEqual([], [e for e in events if e["kind"] == "mode_changed"])


if __name__ == "__main__":
    unittest.main()
