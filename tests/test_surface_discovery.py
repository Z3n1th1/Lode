from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from agents.surface_discovery import SurfaceScope, discover_surface, write_surface_outputs


ROOT = Path(__file__).resolve().parent / "fixtures" / "intel"


class SrcSurfaceDiscoveryTests(unittest.TestCase):
    def test_aegispilot_rules_are_available_on_pentest_agent_side(self) -> None:
        html = (ROOT / "surface.html").read_text(encoding="utf-8")
        script = b'fetch("/api/internal"); fetch("https://api.example.com/from-js"); //# sourceMappingURL=app.js.map'
        source_map = json.dumps({"version": 3, "sources": ["src/router.js"], "sourcesContent": ['fetch("/api/from-map")']}).encode()
        openapi = json.dumps({"openapi": "3.0.0", "paths": {"/api/v1/users": {}, "/graphql": {}}}).encode()

        def fetcher(url: str, **kwargs):
            del kwargs
            if url.endswith("/static/app.js"):
                return 200, script.decode(), {"content-type": "application/javascript"}
            if url.endswith("/static/app.js.map"):
                return 200, source_map.decode(), {"content-type": "application/json"}
            if url.endswith("/openapi.json"):
                return 200, openapi.decode(), {"content-type": "application/json"}
            if url.rstrip("/") == "https://example.com":
                return 200, html, {"content-type": "text/html"}
            return 404, "", {"content-type": "text/plain"}

        scope = SurfaceScope(
            program="fixture-src",
            authorization="written authorization fixture",
            allowed_domains=("example.com",),
            delay_seconds=0.1,
        )
        result = discover_surface(scope, "https://example.com", max_scripts=10, fetcher=fetcher)
        self.assertEqual(200, result.status)
        self.assertIn("/api/v1/docs", result.paths)
        self.assertIn("/api/internal", result.paths)
        self.assertIn("/api/from-map", result.paths)
        self.assertIn("/api/v1/users", result.paths)
        self.assertIn("https://api.example.com/from-js", result.api_urls)
        self.assertNotIn("https://outside.example.net/no", result.api_urls)
        self.assertIn("OpenAPI JSON", result.fingerprints)
        self.assertLessEqual(len(result.requests), 1 + 20 + 3)

    def test_target_outside_scope_is_rejected_before_get(self) -> None:
        scope = SurfaceScope(
            program="fixture-src",
            authorization="written authorization fixture",
            allowed_domains=("example.com",),
            delay_seconds=0.1,
        )
        with self.assertRaisesRegex(ValueError, "target_rejected"):
            discover_surface(scope, "https://outside.example.net", fetcher=lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("no GET")))

    def test_state_changing_get_target_is_rejected_before_fetch(self) -> None:
        scope = SurfaceScope("fixture-src", "authorized", allowed_domains=("example.com",), delay_seconds=0.1)
        for path in ("/logout", "/api/deleteUser", "/api/%2564elete", "/rpc?action=sendEmail", "/rpc?_method=POST"):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "target_rejected"):
                discover_surface(scope, "https://example.com" + path,
                                 fetcher=lambda *args, **kwargs: self.fail("unsafe GET reached fetcher"))

    def test_state_changing_script_link_is_not_requested(self) -> None:
        requested = []
        def fetcher(url, **kwargs):
            requested.append(url)
            html = '<script src="/delete/account.js"></script><script src="/app.js?v=1"></script>'
            return (200, html, {}) if url == "https://example.com/" else (404, "", {})
        result = discover_surface(SurfaceScope("fixture-src", "authorized", allowed_domains=("example.com",), delay_seconds=0),
                                  "https://example.com", fetcher=fetcher)
        self.assertNotIn("https://example.com/delete/account.js", requested)
        self.assertIn("https://example.com/app.js?v=1", requested)
        self.assertTrue(any("state_changing_url" in error for error in result.errors))

    def test_a_redirect_is_followed_one_hop_and_becomes_the_base(self) -> None:
        """回 301/302 的站以前一个字节都取不到 —— 面是空的,看着像"没东西"。

        跟一跳之后,落地的地址才是这个站的根:相对脚本要按它解析,不能挂回旧根。
        """
        requested: list[str] = []

        def fetcher(url, **kwargs):
            del kwargs
            requested.append(url)
            if url == "https://www.example.com/":
                return 301, "", {"location": "https://app.example.com/home/"}
            if url == "https://app.example.com/home/":
                return 200, '<script src="/static/app.js"></script>', {"content-type": "text/html"}
            return 404, "", {}

        result = discover_surface(
            SurfaceScope("fixture-src", "authorized", allowed_domains=("example.com",), delay_seconds=0),
            "https://www.example.com", max_scripts=1, fetcher=fetcher)

        self.assertEqual(200, result.status)
        self.assertEqual("https://app.example.com/home/", result.final_url)
        self.assertIn("https://app.example.com/home/", requested)
        # 相对链接按落地地址解析 —— 没 rebase 的话这里会是 www.example.com
        self.assertIn("https://app.example.com/static/app.js", result.scripts)

    def test_a_redirect_out_of_scope_is_not_followed(self) -> None:
        """重定向能指向任何地方,所以跳过去的目标必须重新过 scope 闸门。

        放行一个越界的 302 等于把"只能打清单内的主机"这条规矩交给被扫的站去决定。
        """
        requested: list[str] = []

        def fetcher(url, **kwargs):
            del kwargs
            requested.append(url)
            if url == "https://www.example.com/":
                return 302, "", {"location": "https://outside.example.net/"}
            return 404, "", {}

        result = discover_surface(
            SurfaceScope("fixture-src", "authorized", allowed_domains=("example.com",), delay_seconds=0),
            "https://www.example.com", max_scripts=0, fetcher=fetcher)

        # 原样返回那个 3xx,不假装跳成功了
        self.assertEqual(302, result.status)
        self.assertEqual("", result.final_url)
        self.assertNotIn("https://outside.example.net/", requested)
        self.assertTrue(any("blocked:" in error for error in result.errors))

    def test_outputs_are_replayable_json_and_markdown(self) -> None:
        result = discover_surface(
            SurfaceScope("fixture-src", "authorized", allowed_domains=("example.com",), delay_seconds=0.1),
            "https://example.com",
            fetcher=lambda url, **kwargs: (200, "<html></html>", {"content-type": "text/html"}) if url.rstrip("/") == "https://example.com" else (404, "", {}),
        )
        with tempfile.TemporaryDirectory() as tmp:
            json_path, md_path = write_surface_outputs(result, tmp)
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual("SrcSurfaceResult/v1", payload["schema"])
            self.assertIn("Candidate paths", md_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
