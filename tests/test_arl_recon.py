"""ARL-Friend distill: ingest, GET fingerprints, WIH tags, pullable case cards."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from intel.arl_ingest import exact_hosts, is_cdn_host, looks_like_arl, parse_arl
from intel.fingerprint import match_body, probe_host, seed_paths
from intel.providers.file import FileProvider
from intel.wih import tag_text
from intel.models import IntelQuery


ROOT = Path(__file__).resolve().parent / "fixtures" / "intel"


def _query() -> IntelQuery:
    return IntelQuery.from_mapping({
        "program": "fixture-src",
        "authorization": "written authorization fixture",
        "allowed_domains": ["example.com"],
        "seed_urls": ["https://example.com/"],
    })


class ArlIngestTests(unittest.TestCase):
    def test_export_drops_cdn_and_keeps_exact_hosts(self) -> None:
        decoded = json.loads((ROOT / "arl-export.json").read_text(encoding="utf-8"))
        self.assertTrue(looks_like_arl(decoded))
        items = parse_arl(decoded)
        values = {item.value for item in items}
        self.assertIn("https://nacos.example.com/nacos/", values)
        self.assertIn("api.example.com", values)
        self.assertTrue(is_cdn_host("img.alicdn.com"))
        self.assertFalse(any("alicdn" in item.value for item in items))
        self.assertIn("https://evil.other.net/admin", values)

    def test_lode_candidate_lists_are_not_arl(self) -> None:
        rows = json.loads((ROOT / "candidates.json").read_text(encoding="utf-8"))
        self.assertFalse(looks_like_arl(rows))

    def test_file_provider_parses_arl_and_scope_filter_drops_foreign(self) -> None:
        from intel.runner import collect

        report = collect(_query(), [FileProvider(ROOT / "arl-export.json")], max_items=20)
        hosts = exact_hosts(report.candidates)
        self.assertEqual({"nacos.example.com", "api.example.com"}, set(hosts))
        self.assertGreaterEqual(report.filtered_count, 1)

    def test_jsonl_site_rows_are_ingested(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sites.jsonl"
            path.write_text(
                json.dumps({"site": "https://api.example.com/"}) + "\n",
                encoding="utf-8",
            )
            items = FileProvider(path).collect(_query(), timeout=1, max_items=10)
        self.assertEqual("https://api.example.com/", items[0].value)
        self.assertIn("arl-export", items[0].tags)


class FingerprintTests(unittest.TestCase):
    def test_seed_paths_are_unique_and_outside_the_default_tax(self) -> None:
        from agents.surface_discovery import SEED_PATHS

        paths = seed_paths()
        self.assertEqual(len(paths), len(set(paths)))
        self.assertTrue(paths)
        self.assertTrue(set(paths) - set(SEED_PATHS), "catalog must add paths, not only aliases")

    def test_match_body_needs_the_marker(self) -> None:
        self.assertEqual(("nacos",), match_body("<title>Nacos</title>"))
        self.assertEqual((), match_body("<html><body>welcome</body></html>"))

    def test_probe_host_is_get_existence_not_exploit(self) -> None:
        requested = []

        def fetcher(url: str, timeout: float = 8.0, max_bytes: int = 200_000):
            del timeout, max_bytes
            requested.append(url)
            if url.endswith("/nacos/") or url.rstrip("/").endswith("/nacos"):
                return 200, "<title>Nacos</title>", {}
            return 404, "not found", {}

        hits = probe_host("https://nacos.example.com", fetcher=fetcher)
        self.assertTrue(requested)
        self.assertTrue(all(item.startswith("https://nacos.example.com/") for item in requested))
        self.assertEqual(["nacos"], [item.title for item in hits])
        self.assertIn("nacos", hits[0].tags)
        self.assertEqual("arl-fingerprint", hits[0].source)

    def test_probe_catalog_avoids_sensitive_read_endpoints(self) -> None:
        paths = set(seed_paths())
        self.assertFalse(any(
            marker in path.lower()
            for path in paths
            for marker in ("/auth/users", "/actuator/env", "/_catalog", "/webapp.json")
        ))
        self.assertIn("/actuator/health", paths)


class WihTests(unittest.TestCase):
    def test_tags_shapes_and_drops_the_secret(self) -> None:
        blob = 'const k = "LTAI1234567890abcd"; eyJhbGciOiJIUzI1NiJ9.aaaaaaaaaaaaaaaa'
        tags = tag_text(blob)
        self.assertIn("aliyun-ak-shape", tags)
        self.assertIn("jwt-shape", tags)
        self.assertNotIn("LTAI1234567890abcd", tags)


class ExtraSeedSurfaceTests(unittest.TestCase):
    def test_extra_seeds_book_fingerprint_spend_and_match_markers(self) -> None:
        from agents.surface_discovery import SurfaceScope, discover_surface
        from intel.fingerprint import seed_paths as fingerprint_paths

        index = "<html><body>welcome</body></html>"
        extra = fingerprint_paths()

        def fetcher(url: str, **kwargs):
            del kwargs
            if url.rstrip("/") == "https://example.com":
                return 200, index, {"content-type": "text/html"}
            if "/nacos/" in url or url.endswith("/nacos"):
                return 200, "<title>Nacos</title>", {"content-type": "text/html"}
            return 404, "", {"content-type": "text/plain"}

        scope = SurfaceScope(
            "fixture-src", "written authorization", allowed_domains=("example.com",),
            delay_seconds=0,
        )
        result = discover_surface(
            scope, "https://example.com", max_scripts=1, fetcher=fetcher, extra_seeds=extra,
        )
        self.assertIn("nacos", result.fingerprints)
        self.assertGreater(result.probe_spend.get("fingerprint", 0), 0)


class KnowledgeAndToggleTests(unittest.TestCase):
    def test_new_cards_are_pullable(self) -> None:
        from core import skills

        names = set(skills.knowledge_catalogue())
        for card in ("case-index", "arl-recon", "sandbox-escape-test"):
            self.assertIn(card, names)
            got = skills.read_knowledge(card)
            self.assertNotIn("error", got, card)
            self.assertTrue(got.get("text"), card)

    def test_knowledge_seed_puts_specific_cards_before_the_recon_floor(self) -> None:
        from console.jobs import _knowledge_seed

        scope = SimpleNamespace(priority_objectives=("rce",))
        seed = _knowledge_seed("对照以前的工作流案例", {"arl_next": True}, scope)
        self.assertEqual("evidence", seed[0])
        self.assertIn("arl-recon", seed)
        self.assertIn("sandbox-escape-test", seed)
        self.assertIn("case-index", seed)
        self.assertIn("orphan-origin-test", seed)
        self.assertLess(seed.index("arl-recon"), seed.index("recon"))

    def test_option_enabled_reads_the_receipt_not_the_digest(self) -> None:
        from console.jobs import _option_enabled

        confirmed = {"options": {"arl_next": {"enabled": True, "mode": "fingerprint_import"}}}
        self.assertTrue(_option_enabled(confirmed, "arl_next"))
        self.assertFalse(_option_enabled(confirmed, "fingerprint"))
        self.assertFalse(_option_enabled({}, "arl_next"))
        self.assertFalse(_option_enabled({"options": "nope"}, "arl_next"))

    def test_precise_fingerprint_toggle_activates_only_the_safe_probe_catalog(self) -> None:
        from console.jobs import _arl_extra_seeds, _knowledge_seed

        self.assertEqual((), _arl_extra_seeds({}))
        self.assertEqual(seed_paths(), _arl_extra_seeds({"fingerprint_precise": True}))
        seed = _knowledge_seed("精确识别公开服务", {"fingerprint_precise": True}, SimpleNamespace())
        self.assertNotIn("arl-recon", seed)

    def test_default_arl_mode_is_fingerprint_import(self) -> None:
        from core.intake_state import default_options

        self.assertEqual("fingerprint_import", default_options()["arl_next"]["mode"])
        self.assertFalse(default_options()["arl_next"]["enabled"])


class ReconCliTests(unittest.TestCase):
    def test_recon_import_writes_exact_hosts(self) -> None:
        from lode import build_parser, cmd_recon

        parser = build_parser()
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            args = parser.parse_args([
                "recon",
                "--scope", str(ROOT / "scope.json"),
                "--out-dir", str(out),
                "--arl-export", str(ROOT / "arl-export.json"),
            ])
            self.assertEqual(0, cmd_recon(args))
            hosts = (out / "hosts.txt").read_text(encoding="utf-8").splitlines()
            self.assertEqual({"nacos.example.com", "api.example.com", "example.com"}, set(hosts))
            summary = json.loads((out / "recon-summary.json").read_text(encoding="utf-8"))
            self.assertEqual("LodeReconSummary/v1", summary["schema"])
            self.assertEqual(0, summary["fingerprint_hits"])

    def test_scan_flag_is_off_by_default(self) -> None:
        from lode import build_parser

        args = build_parser().parse_args(["scan", "https://example.com/", "--scope", "s.json"])
        self.assertFalse(args.arl_next)

    def test_precise_fingerprint_cli_alias_enables_the_probe_catalog(self) -> None:
        from lode import build_parser

        args = build_parser().parse_args([
            "scan", "https://example.com/", "--scope", "s.json", "--fingerprint-precise",
        ])
        self.assertTrue(args.arl_next)


if __name__ == "__main__":
    unittest.main()
