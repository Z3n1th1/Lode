from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path

from intel.models import IntelQuery
from intel.providers.crtsh import CrtShProvider
from intel.providers.cisa_kev import CisaKevProvider
from intel.providers.feed import FeedProvider
from intel.providers.file import FileProvider
from intel.providers.seed import SeedProvider
from intel.providers.twitter import TwitterProvider
from intel.runner import collect, run_watch
from intel.feishu_sink import send_report
from intel.store import IntelStore


ROOT = Path(__file__).resolve().parent / "fixtures" / "intel"


class IntelPipelineTests(unittest.TestCase):
    def query(self) -> IntelQuery:
        return IntelQuery.from_mapping({
            "program": "fixture-src",
            "authorization": "written authorization fixture",
            "allowed_domains": ["example.com"],
            "seed_urls": ["https://example.com/"],
        })

    def test_legacy_intel_surface_provider_is_blocked(self) -> None:
        from intel.providers.surface import SurfaceProvider

        with self.assertRaisesRegex(RuntimeError, "moved_to_pentest_agent"):
            SurfaceProvider()

    def test_crtsh_filters_wildcard_duplicates_and_foreign_hosts(self) -> None:
        payload = (ROOT / "crtsh.json").read_bytes()

        def fetcher(url: str, **kwargs) -> bytes:
            self.assertIn("crt.sh", url)
            return payload

        items = CrtShProvider(fetcher).collect(self.query(), timeout=1, max_items=20)
        self.assertEqual(["api.example.com", "cdn.example.com"], [item.value for item in items])

    def test_cisa_kev_emits_structured_public_cve_intel(self) -> None:
        payload = (ROOT / "cisa-kev.json").read_bytes()
        report = collect(self.query(), [CisaKevProvider(fetcher=lambda *args, **kwargs: payload)], max_items=20)
        self.assertEqual(1, len(report.candidates))
        item = report.candidates[0]
        self.assertEqual("cve", item.kind)
        self.assertIn("CVE-2026-12345", item.title)
        self.assertIn("Apply vendor mitigations", item.summary)
        self.assertGreaterEqual(item.score, 60)

    def test_feed_is_scope_filtered_and_duplicate_is_merged(self) -> None:
        feed = (ROOT / "feed.xml").read_bytes()

        def fetcher(url: str, **kwargs) -> bytes:
            return feed

        report = collect(
            self.query(),
            [SeedProvider(), FeedProvider("fixture-rss", "https://feed.example.org/rss", fetcher=fetcher), FileProvider(ROOT / "candidates.json")],
            store=None,
            max_items=20,
        )
        values = {item.value for item in report.candidates}
        self.assertIn("https://example.com/", values)
        self.assertIn("https://api.example.com/docs", values)
        self.assertIn("https://outside.example.net/admin", values)
        self.assertTrue(any(item.kind == "article" and item.value == "https://outside.example.net/admin" for item in report.candidates))
        article = next(item for item in report.candidates if item.value == "https://outside.example.net/admin")
        self.assertEqual("Foreign research", article.title)
        self.assertIn("metadata only", article.summary)
        self.assertGreaterEqual(report.filtered_count, 1)
        self.assertGreaterEqual(report.duplicate_count, 1)

    def test_target_card_host_does_not_authorize_subdomain_expansion(self) -> None:
        query = IntelQuery.from_mapping({
            "schema": "TargetCard/v1",
            "target_id": "example-1",
            "scope": {"allowed_hosts": ["example.com"], "forbidden_hosts": []},
            "entrypoints": ["https://example.com/"],
        })
        report = collect(query, [SeedProvider(), CrtShProvider(lambda *args, **kwargs: (ROOT / "crtsh.json").read_bytes())], max_items=20)
        self.assertEqual(["https://example.com/"], [item.value for item in report.candidates])

    def test_store_marks_new_then_existing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = IntelStore(tmp)
            first = collect(self.query(), [SeedProvider()], store=store, run_id="first")
            second = collect(self.query(), [SeedProvider()], store=store, run_id="second")
            self.assertTrue(first.candidates[0].is_new)
            self.assertFalse(second.candidates[0].is_new)
            self.assertTrue((Path(tmp) / "runs" / "second" / "candidates.jsonl").is_file())
            self.assertTrue((Path(tmp) / "runs" / "second" / "candidates.csv").is_file())

    def test_file_provider_accepts_json_and_does_not_execute_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "candidates.json"
            path.write_text(json.dumps([{"value": "api.example.com", "kind": "hostname"}]), encoding="utf-8")
            items = FileProvider(path).collect(self.query(), timeout=1, max_items=10)
            self.assertEqual("api.example.com", items[0].value)

    def test_watch_completes_bounded_runs_and_persists_state(self) -> None:
        class StableProvider:
            id = "fixture-watch"

            def collect(self, query, *, timeout, max_items):
                return [{"value": "api.example.com", "kind": "hostname", "source": self.id, "tags": ["api"]}]

        with tempfile.TemporaryDirectory() as tmp:
            summary = run_watch(
                self.query(), [StableProvider()], store=IntelStore(tmp), interval_sec=1,
                max_runs=2, sleep_fn=lambda _: None,
            )
            self.assertEqual("completed", summary.status)
            self.assertEqual(2, summary.runs_completed)
            state = IntelStore(tmp).read_watch_state()
            self.assertEqual("completed", state["status"])
            self.assertEqual(2, state["runs_completed"])

    def test_watch_stops_on_event_and_stops_after_repeated_all_source_failures(self) -> None:
        class BrokenProvider:
            id = "broken-watch"

            def collect(self, query, *, timeout, max_items):
                raise OSError("fixture unavailable")

        with tempfile.TemporaryDirectory() as tmp:
            stop_event = threading.Event()
            summary = run_watch(
                self.query(), [BrokenProvider()], store=IntelStore(tmp), interval_sec=1,
                max_consecutive_errors=2, sleep_fn=lambda _: stop_event.set(), stop_event=stop_event,
            )
            self.assertEqual("stopped", summary.status)
            self.assertEqual(1, summary.runs_completed)

        with tempfile.TemporaryDirectory() as tmp:
            summary = run_watch(
                self.query(), [BrokenProvider()], store=IntelStore(tmp), interval_sec=1,
                max_consecutive_errors=2, sleep_fn=lambda _: None,
            )
            self.assertEqual("failed", summary.status)
            self.assertEqual(2, summary.runs_completed)

    def test_twitter_provider_uses_bearer_token_and_only_emits_in_scope_urls(self) -> None:
        payload = (ROOT / "twitter.json").read_bytes()
        seen_headers = []

        def fetcher(url: str, **kwargs) -> bytes:
            seen_headers.append(kwargs.get("headers") or {})
            return payload

        report = collect(self.query(), [TwitterProvider("fixture-twitter", "example.com", fetcher=fetcher, bearer_token="fixture-token")], max_items=20)
        self.assertEqual("Bearer fixture-token", seen_headers[0]["Authorization"])
        self.assertIn("https://api.example.com/changelog", [item.value for item in report.candidates])
        self.assertTrue(any(item.kind == "social_post" for item in report.candidates))

    def test_feishu_digest_is_redacted_and_dry_run(self) -> None:
        report = collect(self.query(), [SeedProvider()], max_items=20)
        with tempfile.TemporaryDirectory() as tmp:
            result = send_report(report, program="fixture-src", store_root=tmp, dry_run=True)
        self.assertTrue(result["ok"])
        self.assertTrue(result["dry_run"])
        self.assertIn("公开安全情报新增", result["payload"]["content"]["text"])


if __name__ == "__main__":
    unittest.main()
