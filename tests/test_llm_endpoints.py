"""Tests for the Console LLM-settings endpoints and the intake scope sanitiser."""
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

from console.app import create_app

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


class AuthTests(_ConsoleTestCase):
    def test_new_endpoints_require_session(self) -> None:
        calls = [
            ("get", "/api/v1/llm/settings", None),
            ("put", "/api/v1/llm/settings", {"providers": [], "tiers": {}}),
            ("post", "/api/v1/llm/test", {}),
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


if __name__ == "__main__":
    unittest.main()
