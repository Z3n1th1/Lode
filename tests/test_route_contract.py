"""P0 safety net: freeze the Console route contract + characterize key endpoints.

The route contract is the guard rail for the control-plane split (P2): any route
that is added, renamed or accidentally dropped must be an intentional edit here.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT))
sys.path.insert(0, str(_PROJECT_ROOT / "core"))

from fastapi.testclient import TestClient  # noqa: E402

from console.app import create_app  # noqa: E402

PASSWORD = "strong-local-password"
SESSION_SECRET = "session-secret-for-test-0123456789"

# Frozen (method, path) set produced by create_app().
# P2 removed the phantom-module routes (/keys*, /fingerprint, /sink-kb, /poc,
# /socks, /egress, /evolve, /proxy/subscriptions), the /dsh + /arl proxies and
# the intel routes. P5 removed the whole /src-agent/* surface (run + session
# management + chat, plus the H1 LLM intake) now that the unified conversation
# drives the same durable jobs. P5-b turned /project/intake into the real gate,
# which needs three more routes (confirm / discard / pending). Deliberately 40
# entries.
ROUTE_CONTRACT = frozenset({
    ("*", "/assets"),
    ("GET", "/"),
    ("GET", "/{path:path}"),
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
    # findings / report
    ("GET", "/api/v1/findings"),
    ("GET", "/api/v1/report"),
    # projects / tasks / conversation
    ("GET", "/api/v1/proxy"),
    ("GET", "/api/v1/profiles"),
    ("GET", "/api/v1/task"),
    ("GET", "/api/v1/projects"),
    ("GET", "/api/v1/project"),
    ("GET", "/api/v1/trajectory"),
    ("POST", "/api/v1/session/guidance"),
    ("GET", "/api/v1/session/guidance"),
    ("POST", "/api/v1/project/intake"),
    ("POST", "/api/v1/project/intake/confirm"),
    ("POST", "/api/v1/project/intake/discard"),
    ("GET", "/api/v1/project/intake/pending"),
    ("GET", "/api/v1/project/intakes"),
    # 授权文档那条路:一份 scope 文档 → 一次确认 → 每台主机一个 job。和手打 URL
    # 共用同一个待确认槽,只是确认的是文档而不是一个目标。
    ("POST", "/api/v1/project/engagement/preview"),
    ("POST", "/api/v1/project/engagement/confirm"),
    ("POST", "/api/v1/project/engagement/discard"),
    ("GET", "/api/v1/project/results"),
    # durable jobs + unified conversation stream (P3)
    ("GET", "/api/v1/jobs"),
    ("GET", "/api/v1/jobs/{job_id}"),
    ("POST", "/api/v1/jobs/{job_id}/stop"),
    ("GET", "/api/v1/chat/sessions/{session_id}/stream"),
    # unified conversation + modes (P4)
    ("GET", "/api/v1/modes"),
    ("POST", "/api/v1/chat/sessions"),
    ("GET", "/api/v1/chat/sessions/{session_id}/events"),
    ("POST", "/api/v1/chat/sessions/{session_id}/messages"),
    ("POST", "/api/v1/chat/sessions/{session_id}/turn/stop"),
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

    def build(self):
        app = create_app(
            state_dir=self.state_dir, password=PASSWORD,
            session_secret=SESSION_SECRET, static_dir=self.static_dir,
        )
        client = TestClient(app)
        client.__enter__()
        self.addCleanup(client.__exit__, None, None, None)
        return client


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
            ("GET", "/api/v1/llm/settings", None),
            ("GET", "/api/v1/dashboard", None),
            ("GET", "/api/v1/chat/sessions/src-abc1234567/events", None),
            ("GET", "/api/v1/chat/sessions/src-abc1234567/stream", None),
            ("POST", "/api/v1/chat/sessions/src-abc1234567/messages", {"text": "hi"}),
        ):
            with self.subTest(path=path):
                resp = client.request(method, path, json=body)
                self.assertEqual(401, resp.status_code, resp.text)

    def test_healthz_is_public(self) -> None:
        client = self.build()
        resp = client.get("/healthz")
        self.assertEqual(200, resp.status_code)
        self.assertEqual("required", resp.json()["authentication"])


if __name__ == "__main__":
    unittest.main()
