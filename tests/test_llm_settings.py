"""Tests for core.llm_settings — local LLM provider config and env projection."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT))
sys.path.insert(0, str(_PROJECT_ROOT / "core"))

from core import llm_settings

_MANAGED_ENV = (
    "LLM_PROVIDERS", "LLM_API_KEY", "LLM_BASE_URL", "LLM_MODEL",
    "SRC_REASONER_PREFER", "SRC_EXPLORER_PREFER", "LLM_ACTIVE_PROVIDER_FILE",
)


class _SettingsTestCase(unittest.TestCase):
    """Isolate the env vars this module projects."""

    def setUp(self) -> None:
        self._saved = {key: os.environ.get(key) for key in _MANAGED_ENV}
        for key in _MANAGED_ENV:
            os.environ.pop(key, None)

    def tearDown(self) -> None:
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


class MaskTests(_SettingsTestCase):
    def test_mask_never_returns_the_key(self) -> None:
        doc = {
            "schema": llm_settings.SCHEMA,
            "updated_at": 1.0,
            "providers": [{
                "name": "smart", "base_url": "https://api.deepseek.com",
                "model": "deepseek-reasoner", "api_key": "sk-secret-abcd1234",
            }],
            "tiers": {"reasoner": "smart", "explorer": ""},
        }
        masked = llm_settings.mask_settings(doc)
        serialized = json.dumps(masked)
        self.assertNotIn("sk-secret-abcd1234", serialized)
        self.assertNotIn("api_key", serialized)
        provider = masked["providers"][0]
        self.assertTrue(provider["key_set"])
        self.assertEqual("1234", provider["key_hint"])

    def test_mask_reports_missing_key(self) -> None:
        masked = llm_settings.mask_settings({
            "schema": llm_settings.SCHEMA, "providers": [{"name": "x", "base_url": "https://a", "model": "m", "api_key": ""}],
            "tiers": {},
        })
        self.assertFalse(masked["providers"][0]["key_set"])
        self.assertEqual("", masked["providers"][0]["key_hint"])


class PersistenceTests(_SettingsTestCase):
    def test_write_is_atomic_and_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "llm_settings.json"
            doc = llm_settings.write_settings(
                [{"name": "smart", "base_url": "https://api.deepseek.com", "model": "r1", "api_key": "sk-aaaa1111"}],
                {"reasoner": "smart", "explorer": ""},
                path=path,
            )
            self.assertTrue(path.is_file())
            self.assertFalse((path.parent / (".' + path.name + '.tmp'")).exists())
            self.assertFalse((path.with_name("." + path.name + ".tmp")).exists())
            self.assertEqual("smart", doc["providers"][0]["name"])
            reread = llm_settings.read_settings(path)
            self.assertEqual(["smart"], [p["name"] for p in reread["providers"]])

    def test_keyless_update_keeps_the_stored_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "llm_settings.json"
            llm_settings.write_settings(
                [{"name": "smart", "base_url": "https://a.test", "model": "r1", "api_key": "sk-keep-me"}],
                {}, path=path,
            )
            stored = llm_settings.read_settings(path)
            doc = llm_settings.write_settings(
                [{"name": "smart", "base_url": "https://a.test", "model": "r2", "api_key": ""}],
                {}, path=path, stored=stored,
            )
            self.assertEqual("sk-keep-me", doc["providers"][0]["api_key"])
            self.assertEqual("r2", doc["providers"][0]["model"])

    def test_explicit_clear_key_drops_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "llm_settings.json"
            llm_settings.write_settings(
                [{"name": "n", "base_url": "https://a.test", "model": "m", "api_key": "sk-drop"}],
                {}, path=path,
            )
            stored = llm_settings.read_settings(path)
            doc = llm_settings.write_settings(
                [{"name": "n", "base_url": "https://a.test", "model": "m", "api_key": "", "clear_key": True}],
                {}, path=path, stored=stored,
            )
            self.assertEqual("", doc["providers"][0]["api_key"])

    def test_corrupt_file_reads_as_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "llm_settings.json"
            path.write_text("{not json", encoding="utf-8")
            self.assertEqual([], llm_settings.read_settings(path)["providers"])


class ValidationTests(_SettingsTestCase):
    def _write(self, providers):
        with tempfile.TemporaryDirectory() as tmp:
            return llm_settings.write_settings(providers, {}, path=Path(tmp) / "s.json")

    def test_rejects_delimiters_that_break_the_env_encoding(self) -> None:
        for bad in (
            [{"name": "a|b", "base_url": "https://x.test", "model": "m", "api_key": "k"}],
            [{"name": "n", "base_url": "https://x.test", "model": "m", "api_key": "key,with,comma"}],
        ):
            with self.assertRaises(ValueError):
                self._write(bad)

    def test_rejects_duplicate_names_and_bad_scheme(self) -> None:
        with self.assertRaises(ValueError):
            self._write([
                {"name": "dup", "base_url": "https://x.test", "model": "m", "api_key": "k"},
                {"name": "dup", "base_url": "https://x.test", "model": "m", "api_key": "k"},
            ])
        with self.assertRaises(ValueError):
            self._write([{"name": "n", "base_url": "ftp://x.test", "model": "m", "api_key": "k"}])

    def test_keyless_provider_is_allowed_and_dropped_from_env(self) -> None:
        doc = llm_settings.write_settings(
            [{"name": "later", "base_url": "https://x.test", "model": "m", "api_key": ""}],
            {}, path=Path(tempfile.mkdtemp()) / "s.json",
        )
        self.assertEqual("", llm_settings.build_providers_env(doc))


class EnvProjectionTests(_SettingsTestCase):
    def _doc(self):
        return {
            "schema": llm_settings.SCHEMA,
            "updated_at": 1.0,
            "providers": [
                {"name": "smart", "base_url": "https://smart.test", "model": "max", "api_key": "sk-smart"},
                {"name": "cheap", "base_url": "https://cheap.test", "model": "mini", "api_key": "sk-cheap"},
            ],
            "tiers": {"reasoner": "smart", "explorer": "cheap"},
        }

    def test_providers_env_and_tier_prefers_are_projected(self) -> None:
        applied = llm_settings.apply_to_environ(self._doc(), force=True)
        self.assertIn("LLM_PROVIDERS", applied)
        self.assertIn("smart|https://smart.test|sk-smart|max", os.environ["LLM_PROVIDERS"])
        self.assertEqual("smart", os.environ["SRC_REASONER_PREFER"])
        self.assertEqual("cheap", os.environ["SRC_EXPLORER_PREFER"])

    def test_default_provider_follows_the_reasoner_tier(self) -> None:
        doc = self._doc()
        chosen = llm_settings.default_provider(doc)
        self.assertEqual("smart", chosen["name"])
        llm_settings.apply_to_environ(doc, force=True)
        self.assertEqual("sk-smart", os.environ["LLM_API_KEY"])
        self.assertEqual("https://smart.test", os.environ["LLM_BASE_URL"])
        self.assertEqual("max", os.environ["LLM_MODEL"])

    def test_existing_env_wins_without_force(self) -> None:
        os.environ["LLM_API_KEY"] = "from-real-env"
        os.environ["LLM_MODEL"] = "preset-model"
        applied = llm_settings.apply_to_environ(self._doc(), force=False)
        self.assertNotIn("LLM_API_KEY", applied)
        self.assertNotIn("LLM_MODEL", applied)
        self.assertEqual("from-real-env", os.environ["LLM_API_KEY"])
        self.assertEqual("preset-model", os.environ["LLM_MODEL"])
        # Non-managed vars still get filled.
        self.assertIn("LLM_PROVIDERS", applied)

    def test_state_dir_sets_the_active_provider_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            llm_settings.apply_to_environ(self._doc(), state_dir=Path(tmp), force=True)
            self.assertEqual(
                str(Path(tmp) / "model_active_provider.json"),
                os.environ["LLM_ACTIVE_PROVIDER_FILE"],
            )

    def test_load_llm_settings_fills_from_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "llm_settings.json"
            llm_settings.write_settings(
                [{"name": "solo", "base_url": "https://solo.test", "model": "m", "api_key": "sk-solo"}],
                {"reasoner": "solo"}, path=path,
            )
            self.assertGreater(llm_settings.load_llm_settings(path), 0)
            self.assertEqual("sk-solo", os.environ["LLM_API_KEY"])


if __name__ == "__main__":
    unittest.main()
