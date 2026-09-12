from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from core import intel_sources


class IntelSourceRegistryTests(unittest.TestCase):
    def test_defaults_and_crud_are_state_dir_scoped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "state"
            defaults = intel_sources.load_sources(state)
            self.assertEqual({"builtin-seed", "builtin-crtsh", "builtin-cisa-kev"}, {item["id"] for item in defaults})
            ok, source_id = intel_sources.add_source({"kind": "rss", "name": "fixture", "url": "https://feed.example.org/rss"}, state)
            self.assertTrue(ok)
            self.assertTrue((state / "sources.json").is_file())
            self.assertTrue(intel_sources.set_enabled(source_id, False, state))
            current = {item["id"]: item for item in intel_sources.load_sources(state)}
            self.assertFalse(current[source_id]["enabled"])
            self.assertTrue(intel_sources.record_status(source_id, "error", item_count=3, error="fixture_failed", state_dir=state))
            current = {item["id"]: item for item in intel_sources.load_sources(state)}
            self.assertEqual("error", current[source_id]["last_status"])
            self.assertEqual(3, current[source_id]["item_count"])
            self.assertTrue(intel_sources.remove_source(source_id, state))
            self.assertFalse(intel_sources.remove_source("builtin-crtsh", state))

    def test_twitter_source_stays_credentialed_and_disabled_until_configured(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "state"
            ok, source_id = intel_sources.add_source({"kind": "twitter", "name": "x", "query": "example.com"}, state)
            self.assertTrue(ok)
            source = {item["id"]: item for item in intel_sources.load_sources(state)}[source_id]
            self.assertFalse(source["enabled"])
            self.assertIn("credentialed", source["tags"])
            ok2, source_id2 = intel_sources.add_source({"kind": "twitter", "name": "x-cve", "query": "CVE-2026"}, state)
            self.assertTrue(ok2)
            self.assertNotEqual(source_id, source_id2)
            self.assertEqual((False, "twitter_query_required"), intel_sources.add_source({"kind": "twitter", "name": "missing-query"}, state))

    def test_private_and_non_http_sources_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "state"
            self.assertEqual((False, "source_host_not_public"), intel_sources.add_source({"kind": "rss", "name": "local", "url": "http://127.0.0.1/feed"}, state))
            ok, reason = intel_sources.add_source({"kind": "rss", "name": "file", "url": "file:///tmp/feed.xml"}, state)
            self.assertFalse(ok)
            self.assertTrue(reason.startswith("source_url_must_be_public_http"))


if __name__ == "__main__":
    unittest.main()
