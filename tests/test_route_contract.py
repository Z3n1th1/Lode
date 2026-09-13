"""P0 safety net: freeze the Console route contract + characterize key endpoints.

The route contract is the guard rail for the control-plane split (P2): any route
that is added, renamed or accidentally dropped must be an intentional edit here.
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT))
sys.path.insert(0, str(_PROJECT_ROOT / "core"))

from fastapi.testclient import TestClient  # noqa: E402

from console.control_plane import create_app  # noqa: E402

PASSWORD = "strong-local-password"
SESSION_SECRET = "session-secret-for-test-0123456789"

# Frozen (method, path) set produced by create_app() at HEAD ba4fa73.
# P2 intentionally removes the phantom-module routes (/fingerprint, /sink-kb,
# /poc, /socks, /egress, /evolve, /proxy/subscriptions), the /dsh + /arl proxies
# and the intel routes; that phase must update this set deliberately.
ROUTE_CONTRACT = frozenset({
    ("*", "/assets"),
    ("GET", "/"),
    ("GET", "/{path:path}"),
    ("GET", "/src-agent"),
    ("GET", "/healthz"),
    ("POST", "/api/v1/session"),
    ("DELETE", "/api/v1/session"),
    # dashboard / system / models
    ("GET", "/api/v1/dashboard"),
    ("GET", "/api/v1/system"),
    ("GET", "/api/v1/models"),
    ("POST", "/api/v1/model/active"),
    ("GET", "/api/v1/src-autopilot"),
    # llm settings
    ("GET", "/api/v1/llm/settings"),
    ("PUT", "/api/v1/llm/settings"),
    ("POST", "/api/v1/llm/test"),
    # src agent run
    ("POST", "/api/v1/src-agent/start"),
    ("GET", "/api/v1/src-agent/status"),
    ("POST", "/api/v1/src-agent/stop"),
    ("POST", "/api/v1/src-agent/intake"),
    ("GET", "/api/v1/src-agent/progress"),
    # src agent chat / sessions
    ("GET", "/api/v1/src-agent/sessions"),
    ("PATCH", "/api/v1/src-agent/sessions/{session_id}"),
    ("DELETE", "/api/v1/src-agent/sessions/{session_id}"),
    ("POST", "/api/v1/src-agent/sessions/prune"),
    ("GET", "/api/v1/src-agent/history"),
    ("POST", "/api/v1/src-agent/chat"),
    ("GET", "/api/v1/src-agent/events"),
    # findings / keys
    ("GET", "/api/v1/findings"),
    ("GET", "/api/v1/keys"),
    ("POST", "/api/v1/keys/unlock"),
    ("POST", "/api/v1/keys/lock"),
    ("GET", "/api/v1/report"),
    # projects / tasks / conversation
    ("GET", "/api/v1/proxy"),
    ("GET", "/api/v1/profiles"),
    ("GET", "/api/v1/task"),
    ("GET", "/api/v1/projects"),
    ("GET", "/api/v1/project"),
    ("GET", "/api/v1/trajectory"),
    ("GET", "/api/v1/conversation"),
    ("GET", "/api/v1/conversation/stream"),
    ("POST", "/api/v1/session/guidance"),
    ("GET", "/api/v1/session/guidance"),
    ("POST", "/api/v1/project/intake"),
    ("GET", "/api/v1/project/intakes"),
    ("GET", "/api/v1/project/results"),
    # intel (deleted in P2)
    ("GET", "/api/v1/intel"),
    ("GET", "/api/v1/fleet"),
    ("GET", "/api/v1/asset-changes"),
    ("GET", "/api/v1/intel/sources"),
    ("GET", "/api/v1/intel/watch"),
    ("POST", "/api/v1/intel/sources"),
    ("POST", "/api/v1/intel/sources/toggle"),
    ("DELETE", "/api/v1/intel/sources"),
    # phantom-module routes (deleted in P2)
    ("GET", "/api/v1/fingerprint/corrections"),
    ("POST", "/api/v1/fingerprint/correction"),
    ("POST", "/api/v1/fingerprint/correction/decision"),
    ("GET", "/api/v1/sink-kb"),
    ("POST", "/api/v1/sink-kb/decision"),
    ("GET", "/api/v1/poc/pending"),
    ("POST", "/api/v1/poc/confirm"),
    ("GET", "/api/v1/socks"),
    ("POST", "/api/v1/socks/add"),
    ("DELETE", "/api/v1/socks"),
    ("GET", "/api/v1/egress"),
    ("POST", "/api/v1/egress/allow"),
    ("DELETE", "/api/v1/egress/allow"),
    ("GET", "/api/v1/evolve"),
    ("POST", "/api/v1/evolve/decision"),
    ("GET", "/api/v1/proxy/subscriptions"),
    ("POST", "/api/v1/proxy/subscriptions"),
    ("POST", "/api/v1/proxy/subscriptions/toggle"),
    ("DELETE", "/api/v1/proxy/subscriptions"),
    # embedded third-party UIs (deleted in P2)
    *{("GET", p) for p in ("/dsh", "/dsh/{path:path}", "/arl", "/arl/{path:path}")},
    *{("POST", p) for p in ("/dsh", "/dsh/{path:path}", "/arl", "/arl/{path:path}")},
    *{("PUT", p) for p in ("/dsh", "/dsh/{path:path}", "/arl", "/arl/{path:path}")},
    *{("PATCH", p) for p in ("/dsh", "/dsh/{path:path}", "/arl", "/arl/{path:path}")},
    *{("DELETE", p) for p in ("/dsh", "/dsh/{path:path}", "/arl", "/arl/{path:path}")},
    *{("HEAD", p) for p in ("/dsh", "/dsh/{path:path}", "/arl", "/arl/{path:path}")},
    *{("OPTIONS", p) for p in ("/dsh", "/dsh/{path:path}", "/arl", "/arl/{path:path}")},
    ("*", "/dsh/{path:path}"),
})


def _collect_routes(app) -> set:
    rows = set()
    for route in app.routes:
        path = getattr(route, "path", None)
        if path is None:
            continue
        methods = getattr(route, "methods", None)
        if methods:
            for method in methods:
                rows.add((method, path))
        else:
            rows.add(("*", path))
    return rows


class _ConsoleCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.state_dir = root / "state"
        static = root / "static"
        (static / "assets").mkdir(parents=True)
        (static / "index.html").write_text("<html></html>", encoding="utf-8")
        self.static_dir = static

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def build(self, *, patch_chat=None):
        ctx = patch("agents.src_chat.chat", patch_chat) if patch_chat else None
        if ctx:
            ctx.start()
        try:
            app = create_app(
                state_dir=self.state_dir, password=PASSWORD,
                session_secret=SESSION_SECRET, static_dir=self.static_dir,
            )
        finally:
            if ctx:
                ctx.stop()
        client = TestClient(app)
        client.__enter__()
        self.addCleanup(client.__exit__, None, None, None)
        return client

    def login(self, client) -> None:
        resp = client.post("/api/v1/session", json={"password": PASSWORD})
        self.assertEqual(204, resp.status_code, resp.text)


class RouteContractTests(_ConsoleCase):
    def test_route_contract_is_frozen(self) -> None:
        client = self.build()
        actual = _collect_routes(client.app)
        missing = sorted(ROUTE_CONTRACT - actual)
        added = sorted(actual - ROUTE_CONTRACT)
        self.assertEqual([], missing, f"routes removed: {missing}")
        self.assertEqual([], added, f"routes added: {added}")


class AuthGateTests(_ConsoleCase):
    def test_protected_routes_require_session(self) -> None:
        client = self.build()
        # Bodies carry valid payloads so FastAPI's request validation does not
        # short-circuit to 422 before the handler's session check runs.
        for method, path, body in (
            ("GET", "/api/v1/src-agent/status", None),
            ("GET", "/api/v1/src-agent/sessions", None),
            ("POST", "/api/v1/src-agent/chat", {"message": "hi"}),
            ("POST", "/api/v1/src-agent/start", {"target_url": "http://example.com"}),
            ("GET", "/api/v1/llm/settings", None),
            ("GET", "/api/v1/dashboard", None),
        ):
            with self.subTest(path=path):
                resp = client.request(method, path, json=body)
                self.assertEqual(401, resp.status_code, resp.text)

    def test_healthz_is_public(self) -> None:
        client = self.build()
        resp = client.get("/healthz")
        self.assertEqual(200, resp.status_code)
        self.assertEqual("required", resp.json()["authentication"])


class SrcAgentCharacterizationTests(_ConsoleCase):
    def test_status_returns_dict_with_status_key(self) -> None:
        client = self.build()
        self.login(client)
        resp = client.get("/api/v1/src-agent/status")
        self.assertEqual(200, resp.status_code, resp.text)
        body = resp.json()
        self.assertIsInstance(body, dict)
        self.assertIn("status", body)
        self.assertNotIn("thread", body)

    def test_stop_when_not_running(self) -> None:
        client = self.build()
        self.login(client)
        resp = client.post("/api/v1/src-agent/stop")
        self.assertEqual(200, resp.status_code, resp.text)
        self.assertEqual({"ok": False, "reason": "not_running"}, resp.json())

    def test_start_rejects_invalid_target(self) -> None:
        client = self.build()
        self.login(client)
        resp = client.post("/api/v1/src-agent/start", json={"target_url": "not-a-url"})
        self.assertEqual(400, resp.status_code, resp.text)
        self.assertEqual("invalid_target", resp.json()["detail"])

    def test_chat_rejects_empty_message(self) -> None:
        client = self.build()
        self.login(client)
        resp = client.post("/api/v1/src-agent/chat", json={"message": "   "})
        self.assertEqual(400, resp.status_code, resp.text)
        self.assertEqual("empty_message", resp.json()["detail"])

    def test_chat_returns_reply_shape(self) -> None:
        client = self.build(patch_chat=lambda session, message, timeout=120.0: "pong")
        self.login(client)
        resp = client.post("/api/v1/src-agent/chat", json={"message": "hi"})
        self.assertEqual(200, resp.status_code, resp.text)
        body = resp.json()
        self.assertEqual("pong", body["reply"])
        self.assertIn("session_id", body)
        self.assertIn("events", body)

    def test_conversation_stream_requires_session(self) -> None:
        client = self.build()
        resp = client.get("/api/v1/conversation/stream")
        self.assertEqual(401, resp.status_code, resp.text)


if __name__ == "__main__":
    unittest.main()
