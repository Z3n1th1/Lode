"""Tests for the Console LLM-settings, H1-intake and session-management endpoints."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT))
sys.path.insert(0, str(_PROJECT_ROOT / "core"))

from fastapi.testclient import TestClient

from console.routers import intake as cp_intake
from console import control_plane as cp
from console import deps as cp_deps
from console.control_plane import create_app

PASSWORD = "strong-local-password"
SESSION_SECRET = "session-secret-for-test-0123456789"


class _ConsoleTestCase(unittest.TestCase):
    _ENV_KEYS = (
        "LLM_PROVIDERS", "LLM_API_KEY", "LLM_BASE_URL", "LLM_MODEL",
        "SRC_REASONER_PREFER", "SRC_EXPLORER_PREFER", "LLM_ACTIVE_PROVIDER_FILE",
    )

    def setUp(self) -> None:
        self._env_saved = {key: os.environ.get(key) for key in self._ENV_KEYS}
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.state_dir = root / "state"
        static = root / "static"
        static.mkdir()
        self.app = create_app(
            state_dir=self.state_dir, password=PASSWORD,
            session_secret=SESSION_SECRET, static_dir=static,
        )
        self.client = TestClient(self.app)
        self.client.__enter__()

    def tearDown(self) -> None:
        self.client.__exit__(None, None, None)
        self._tmp.cleanup()
        for key, value in self._env_saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def login(self) -> None:
        resp = self.client.post("/api/v1/session", json={"password": PASSWORD})
        self.assertEqual(204, resp.status_code)

    def seed_session(self, session_id: str, *, messages=None, blackboard: bool = False) -> Path:
        sess_dir = self.state_dir / "src-chat" / session_id
        sess_dir.mkdir(parents=True, exist_ok=True)
        if messages is not None:
            (sess_dir / "session.json").write_text(json.dumps({
                "schema": "SrcChatSession/v1", "session_id": session_id, "title": "",
                "created_at": 1.0, "last_active": 2.0, "messages": messages, "events": [],
            }), encoding="utf-8")
        if blackboard:
            (sess_dir / "src-blackboard.json").write_text(json.dumps({
                "schema": "SrcBlackboard/v1", "facts": [], "intents": [],
                "dead_ends": [], "hints": [], "claims": [], "events": [],
            }), encoding="utf-8")
        return sess_dir


class AuthTests(_ConsoleTestCase):
    def test_new_endpoints_require_session(self) -> None:
        calls = [
            ("get", "/api/v1/llm/settings", None),
            ("put", "/api/v1/llm/settings", {"providers": [], "tiers": {}}),
            ("post", "/api/v1/llm/test", {}),
            ("post", "/api/v1/src-agent/intake", {}),
            ("get", "/api/v1/src-agent/sessions", None),
            ("post", "/api/v1/src-agent/sessions/prune", None),
            ("patch", "/api/v1/src-agent/sessions/src-aaaa11111111", {"title": "x"}),
            ("delete", "/api/v1/src-agent/sessions/src-aaaa11111111", None),
        ]
        for method, path, body in calls:
            with self.subTest(path=path):
                resp = getattr(self.client, method)(path) if body is None \
                    else getattr(self.client, method)(path, json=body)
                self.assertEqual(401, resp.status_code)


class LlmSettingsEndpointTests(_ConsoleTestCase):
    _PAYLOAD = {
        "providers": [
            {"name": "smart", "base_url": "https://api.deepseek.com",
             "model": "deepseek-reasoner", "api_key": "sk-smart-abcd1234"},
            {"name": "cheap", "base_url": "https://api.deepseek.com",
             "model": "deepseek-chat", "api_key": "sk-cheap-zzzz9999"},
        ],
        "tiers": {"reasoner": "smart", "explorer": "cheap"},
    }

    def test_read_is_empty_then_write_persists_masked(self) -> None:
        self.login()
        first = self.client.get("/api/v1/llm/settings")
        self.assertEqual(200, first.status_code)
        self.assertEqual([], first.json()["providers"])
        self.assertIn("settings_path", first.json())

        resp = self.client.put("/api/v1/llm/settings", json=self._PAYLOAD)
        self.assertEqual(200, resp.status_code)
        body = resp.json()
        self.assertTrue(body["ok"])
        self.assertNotIn("sk-smart-abcd1234", json.dumps(body))
        self.assertNotIn("api_key", json.dumps(body))
        self.assertEqual(["1234", "9999"], [p["key_hint"] for p in body["providers"]])
        self.assertEqual({"reasoner": "smart", "explorer": "cheap"}, body["tiers"])
        self.assertTrue((self.state_dir / "llm_settings.json").is_file())
        self.assertFalse((self.state_dir / ".llm_settings.json.tmp").exists())
        # The running process is updated too, so the next SRC run picks it up.
        self.assertIsInstance(body["applied_env"], list)
        self.assertTrue(os.environ.get("LLM_PROVIDERS", "").startswith("smart|"))
        self.assertEqual("smart", os.environ.get("SRC_REASONER_PREFER"))
        self.assertEqual("cheap", os.environ.get("SRC_EXPLORER_PREFER"))

    def test_keyless_round_trip_keeps_the_stored_keys(self) -> None:
        self.login()
        self.client.put("/api/v1/llm/settings", json=self._PAYLOAD)
        keyless = {
            "providers": [
                {"name": p["name"], "base_url": p["base_url"], "model": p["model"], "api_key": ""}
                for p in self._PAYLOAD["providers"]
            ],
            "tiers": self._PAYLOAD["tiers"],
        }
        body = self.client.put("/api/v1/llm/settings", json=keyless).json()
        self.assertEqual(["smart", "cheap"], [p["name"] for p in body["providers"]])
        self.assertTrue(all(p["key_set"] for p in body["providers"]))

    def test_invalid_provider_is_rejected(self) -> None:
        self.login()
        resp = self.client.put("/api/v1/llm/settings", json={
            "providers": [{"name": "a|b", "base_url": "https://x.test", "model": "m", "api_key": "k"}],
            "tiers": {},
        })
        self.assertEqual(400, resp.status_code)
        self.assertIn("invalid_settings", resp.json()["detail"])

    def test_test_endpoint_rejects_unknown_name(self) -> None:
        self.login()
        self.assertEqual(400, self.client.post("/api/v1/llm/test", json={"name": "nope"}).status_code)

    def test_test_endpoint_reports_failure_as_200(self) -> None:
        self.login()
        failure = {"ok": False, "name": "draft", "model": "m", "latency_ms": 3, "error": "http_401"}
        with patch("core.llm_pool.probe_provider", return_value=failure):
            resp = self.client.post("/api/v1/llm/test", json={
                "provider": {"name": "draft", "base_url": "https://x.test", "model": "m", "api_key": "sk-draft"},
            })
        self.assertEqual(200, resp.status_code)
        self.assertFalse(resp.json()["ok"])
        self.assertEqual("http_401", resp.json()["error"])

    def test_test_endpoint_without_a_key_short_circuits(self) -> None:
        self.login()
        resp = self.client.post("/api/v1/llm/test", json={
            "provider": {"name": "draft", "base_url": "https://x.test", "model": "m", "api_key": ""},
        })
        self.assertEqual(200, resp.status_code)
        self.assertEqual("missing_base_url_or_api_key", resp.json()["error"])


class ScopeNormalizationTests(unittest.TestCase):
    """The LLM's extraction output is untrusted and must be sanitized."""

    def test_wildcards_ips_and_out_of_scope_hosts_are_dropped(self) -> None:
        out = cp._normalize_scope({
            "program": "Acme",
            "in_scope": {
                "domains": ["acme.com", "*.acme.com", "10.0.0.1", "not a domain"],
                "hosts": ["api.acme.com", "127.0.0.1"],
                "urls": ["https://api.acme.com/v1", "https://evil.test/x", "http://127.0.0.1/x"],
            },
            "out_of_scope": ["evil.test"],
            "candidate_targets": ["https://api.acme.com/v1?id=1", "https://evil.test/x", "javascript:alert(1)"],
            "notes": "n",
        })
        self.assertEqual(["acme.com"], out["in_scope"]["domains"])
        self.assertEqual(["api.acme.com"], out["in_scope"]["hosts"])
        self.assertEqual(["https://api.acme.com/v1"], out["in_scope"]["urls"])
        self.assertEqual(["https://api.acme.com/v1?id=1"], out["candidate_targets"])
        self.assertEqual("Acme", out["program"])

    def test_garbage_input_yields_an_empty_draft(self) -> None:
        out = cp._normalize_scope({"in_scope": "not-a-dict", "candidate_targets": "nope"})
        self.assertEqual([], out["in_scope"]["domains"])
        self.assertEqual([], out["candidate_targets"])
        self.assertEqual("", out["program"])


class H1IntakeEndpointTests(_ConsoleTestCase):
    SSRF_TARGETS = (
        "http://127.0.0.1/x",
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost/x",
        "file:///etc/passwd",
        "https://user:pw@example.com",
        "http://[::1]/x",
    )

    def test_ssrf_targets_are_rejected(self) -> None:
        self.login()
        for bad in self.SSRF_TARGETS:
            with self.subTest(url=bad):
                resp = self.client.post("/api/v1/src-agent/intake", json={"url": bad})
                self.assertEqual(400, resp.status_code)

    def test_empty_intake_is_rejected(self) -> None:
        self.login()
        self.assertEqual(400, self.client.post("/api/v1/src-agent/intake", json={}).status_code)

    def test_text_intake_writes_an_audit_copy(self) -> None:
        self.login()
        draft = {"program": "Acme", "in_scope": {"domains": ["acme.com"], "hosts": [], "urls": []},
                 "out_of_scope": [], "candidate_targets": ["https://acme.com/x"], "notes": ""}
        with patch.object(cp_intake, "_extract_scope", return_value={"ok": True, "extracted": draft, "error": ""}):
            resp = self.client.post("/api/v1/src-agent/intake", json={"text": "Acme program: acme.com"})
        self.assertEqual(200, resp.status_code)
        body = resp.json()
        self.assertTrue(body["id"].startswith("LI-"))
        self.assertEqual("Acme", body["extracted"]["program"])
        self.assertTrue((self.state_dir / "llm-intake" / f"{body['id']}.json").is_file())

    def test_url_intake_fetches_then_extracts(self) -> None:
        self.login()
        draft = {"program": "Acme", "in_scope": {"domains": ["acme.com"], "hosts": [], "urls": []},
                 "out_of_scope": [], "candidate_targets": ["https://acme.com/x"], "notes": ""}
        pages = {"https://acme.com/program": (200, {"content-type": "text/html"}, b"<html>acme.com</html>")}
        with patch.object(cp_deps, "_http_get_once", side_effect=lambda url, timeout: pages[url]), \
                patch.object(cp_intake, "_extract_scope", return_value={"ok": True, "extracted": draft, "error": ""}):
            resp = self.client.post("/api/v1/src-agent/intake", json={"url": "https://acme.com/program"})
        self.assertEqual(200, resp.status_code)
        self.assertEqual("https://acme.com/program", resp.json()["source"])

    def test_redirect_into_a_private_host_is_refused(self) -> None:
        self.login()
        pages = {"https://acme.com/go": (302, {"location": "http://127.0.0.1/secret"}, b"")}
        with patch.object(cp_deps, "_http_get_once", side_effect=lambda url, timeout: pages[url]):
            resp = self.client.post("/api/v1/src-agent/intake", json={"url": "https://acme.com/go"})
        self.assertEqual(400, resp.status_code)
        self.assertEqual("invalid_target", resp.json()["detail"])

    def test_llm_unavailable_is_503(self) -> None:
        self.login()
        with patch.object(cp_intake, "_extract_scope", return_value={"ok": False, "extracted": None, "error": "llm_unavailable"}):
            resp = self.client.post("/api/v1/src-agent/intake", json={"text": "x"})
        self.assertEqual(503, resp.status_code)
        self.assertEqual("llm_unavailable", resp.json()["detail"])

    def test_unparseable_extraction_is_502(self) -> None:
        self.login()
        with patch.object(cp_intake, "_extract_scope", return_value={"ok": False, "extracted": None, "error": "extraction_unparseable"}):
            resp = self.client.post("/api/v1/src-agent/intake", json={"text": "x"})
        self.assertEqual(502, resp.status_code)


class SrcSessionEndpointTests(_ConsoleTestCase):
    def test_list_returns_counts_and_hides_junk_dirs(self) -> None:
        self.login()
        self.seed_session("src-aaa11111111", messages=[{"role": "user", "content": "hi"}])
        self.seed_session("src-bbb22222222", messages=[])
        (self.state_dir / "src-chat" / "src-ccc33333333").mkdir(parents=True)  # stray dir
        body = self.client.get("/api/v1/src-agent/sessions").json()
        self.assertEqual(2, body["total"])
        self.assertEqual(1, body["empty_count"])
        ids = [s["session_id"] for s in body["sessions"]]
        self.assertNotIn("src-ccc33333333", ids)
        self.assertFalse([s for s in body["sessions"] if s["session_id"] == "src-aaa11111111"][0]["empty"])

    def test_rename_and_pin(self) -> None:
        self.login()
        self.seed_session("src-aaa11111111", messages=[{"role": "user", "content": "hi"}])
        renamed = self.client.patch("/api/v1/src-agent/sessions/src-aaa11111111", json={"title": "越权测试"})
        self.assertEqual(200, renamed.status_code)
        self.assertEqual("越权测试", renamed.json()["title"])
        pinned = self.client.patch("/api/v1/src-agent/sessions/src-aaa11111111", json={"pinned": True})
        self.assertEqual(200, pinned.status_code)
        self.assertTrue(pinned.json()["pinned"])
        self.assertEqual("越权测试", pinned.json()["title"])

    def test_rename_missing_session_is_404(self) -> None:
        self.login()
        resp = self.client.patch("/api/v1/src-agent/sessions/src-missing0000", json={"title": "x"})
        self.assertEqual(404, resp.status_code)

    def test_patch_without_changes_is_400(self) -> None:
        self.login()
        self.seed_session("src-aaa11111111", messages=[{"role": "user", "content": "hi"}])
        resp = self.client.patch("/api/v1/src-agent/sessions/src-aaa11111111", json={})
        self.assertEqual(400, resp.status_code)

    def test_delete_removes_and_404s_afterwards(self) -> None:
        self.login()
        sess_dir = self.seed_session("src-aaa11111111",
                                     messages=[{"role": "user", "content": "hi"}], blackboard=True)
        self.assertEqual(204, self.client.delete("/api/v1/src-agent/sessions/src-aaa11111111").status_code)
        self.assertFalse(sess_dir.exists())
        self.assertEqual(404, self.client.delete("/api/v1/src-agent/sessions/src-aaa11111111").status_code)

    def test_delete_rejects_traversal_ids(self) -> None:
        self.login()
        for bad in ["..", "src-../../x", "other-abc"]:
            with self.subTest(session_id=bad):
                resp = self.client.delete(f"/api/v1/src-agent/sessions/{bad}")
                self.assertIn(resp.status_code, (400, 404))

    def test_prune_removes_only_empty_workless_sessions(self) -> None:
        self.login()
        self.seed_session("src-empty1111111", messages=[])
        self.seed_session("src-talk2222222", messages=[{"role": "user", "content": "hi"}])
        self.seed_session("src-scan3333333", messages=[], blackboard=True)
        body = self.client.post("/api/v1/src-agent/sessions/prune").json()
        self.assertTrue(body["ok"])
        self.assertEqual(1, body["removed"])
        self.assertEqual(2, body["kept"])


if __name__ == "__main__":
    unittest.main()
