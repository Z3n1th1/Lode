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


class CapabilityDeclarationTests(unittest.TestCase):
    """授权文档现在要说"能做**什么**,不只是"能去**哪**"。

    以前只读是 agents/src_agent.py 里一个硬编码的 {"GET","HEAD"},文档从来没有
    这一维 —— 想放宽只能在源码里放宽,那是把治理从句面搬进代码。
    """

    def _scope(self, **doc):
        return SurfaceScope.from_mapping(doc)

    def test_undeclared_means_read_only(self) -> None:
        """fail-closed 的方向是"还能看",不是"什么都不能"也不是"什么都能"。"""
        scope = self._scope(program="p", authorization="a", allowed_domains=["x.com"])
        self.assertEqual(("GET", "HEAD"), scope.allowed_methods)
        self.assertFalse(scope.allow_request_body)
        self.assertTrue(scope.allows_method("get"))
        self.assertFalse(scope.allows_method("POST"))

    def test_get_and_head_cannot_be_declared_away(self) -> None:
        scope = self._scope(program="p", authorization="a", allowed_hosts=["x.com"],
                            allowed_methods=["DELETE"])
        self.assertIn("GET", scope.allowed_methods)
        self.assertIn("HEAD", scope.allowed_methods)
        self.assertIn("DELETE", scope.allowed_methods)

    def test_a_declared_method_is_normalised_and_ordered(self) -> None:
        """顺序固定、大小写归一:两份声明同一个集合的文档必须比较相等。"""
        scope = self._scope(program="p", authorization="a", allowed_hosts=["x.com"],
                            allowed_methods=["post", "get", "POST", "put"])
        self.assertEqual(("GET", "HEAD", "POST", "PUT"), scope.allowed_methods)
        self.assertEqual(scope.allowed_methods, self._scope(
            program="p", authorization="a", allowed_hosts=["x.com"],
            allowed_methods=["PUT", "POST"]).allowed_methods)

    def test_a_string_method_declaration_is_one_value_not_four_characters(self) -> None:
        """踩过的坑:``for item in (data.get(...) or ())`` 会逐字符迭代字符串。

        "POST" 于是变成 P / O / S / T 四个未知动词 —— 在唯一要紧的那个地方静默
        失效。手写的 scope 文件正是最容易这么写的地方。
        """
        scope = self._scope(program="p", authorization="a", allowed_hosts=["x.com"],
                            allowed_methods="POST")
        self.assertEqual(("GET", "HEAD", "POST"), scope.allowed_methods)
        self.assertTrue(scope.allows_method("POST"))

    def test_unknown_verbs_are_filtered_not_trusted(self) -> None:
        scope = self._scope(program="p", authorization="a", allowed_hosts=["x.com"],
                            allowed_methods=["POST", "TRACE", "CONNECT", "", None])
        self.assertEqual(("GET", "HEAD", "POST"), scope.allowed_methods)

    def test_the_flat_and_nested_shapes_both_work(self) -> None:
        flat = SurfaceScope.from_mapping({
            "program": "p", "authorization": "a", "allowed_hosts": ["x.com"],
            "allowed_methods": ["POST"], "allow_request_body": True,
        })
        nested = SurfaceScope.from_mapping({
            "program": "p", "authorization": "a",
            "scope": {"allowed_hosts": ["x.com"], "allowed_methods": ["POST"],
                      "allow_request_body": True},
        })
        self.assertEqual(("GET", "HEAD", "POST"), flat.allowed_methods)
        self.assertEqual(flat.allowed_methods, nested.allowed_methods)
        self.assertTrue(flat.allow_request_body)
        self.assertTrue(nested.allow_request_body)

    def test_a_body_needs_to_be_asked_for_separately(self) -> None:
        """"可以发 POST"和"可以发任意 body"是两件事。"""
        scope = self._scope(program="p", authorization="a", allowed_hosts=["x.com"],
                            allowed_methods=["POST"])
        self.assertFalse(scope.allow_request_body)
        truthy = self._scope(program="p", authorization="a", allowed_hosts=["x.com"],
                             allow_request_body="yes")
        self.assertTrue(truthy.allow_request_body)


class RateDeclarationTests(unittest.TestCase):
    """速度写在程序文档里的单位是 req/s,delay 是我们的换算结果。

    以前只有 ``surface_delay_seconds`` / ``min_interval_seconds`` —— 程序写 "3 req/s"
    而 scope 文件里得手算成 0.333。手算这件事本身就是错误来源,而且算错的方向几乎
    总是"比承诺的快"。现在 req/s 可以直接写进去,换算由我们做一次,做在一处。
    """

    def _scope(self, **doc):
        return SurfaceScope.from_mapping(doc)

    def test_a_rate_is_taken_as_written(self) -> None:
        scope = self._scope(program="p", authorization="a", allowed_hosts=["x.com"],
                            rate_limit={"requests_per_second": 3})
        self.assertAlmostEqual(1 / 3, scope.delay_seconds, places=6)
        self.assertAlmostEqual(3.0, scope.requests_per_second, places=6)

    def test_a_rate_can_sit_at_the_top_level_too(self) -> None:
        """程序文档长得各不相同,"只能写在 rate_limit 里"是个会被踩的门槛。"""
        scope = self._scope(program="p", authorization="a", allowed_hosts=["x.com"],
                            requests_per_second=2)
        self.assertEqual(0.5, scope.delay_seconds)

    def test_the_rate_wins_over_a_hand_rounded_interval(self) -> None:
        """两个都给的时候按 req/s 走 —— 让 1/3 和 0.333 互相打架没有意义。"""
        scope = self._scope(program="p", authorization="a", allowed_hosts=["x.com"],
                            requests_per_second=4, surface_delay_seconds=2.0)
        self.assertEqual(0.25, scope.delay_seconds)

    def test_a_typo_cannot_become_a_flood(self) -> None:
        """``500`` 当 req/s 用就是 500 req/s;夹住上界比照单全收更像个负责人。"""
        scope = self._scope(program="p", authorization="a", allowed_hosts=["x.com"],
                            requests_per_second=500)
        self.assertEqual(0.1, scope.delay_seconds)
        self.assertAlmostEqual(10.0, scope.requests_per_second, places=6)

    def test_a_rate_too_slow_to_matter_lands_on_the_ceiling_not_on_a_faster_one(self) -> None:
        """比上界更慢的声明被夹到 30s,绝不会被夹快。

        夹一个 *下限* 才是危险的 —— 那会把"一分钟一个请求"悄悄变成十秒一个,等于
        替程序决定它可以被多打。这里钉住方向:夹紧只会更慢。
        """
        scope = self._scope(program="p", authorization="a", allowed_hosts=["x.com"],
                            requests_per_second=0.000_001)
        self.assertEqual(30.0, scope.delay_seconds)

    def test_a_rate_and_an_interval_hit_the_same_wall(self) -> None:
        """两种拼法撞的必须是同一堵墙,否则写错哪个会更快就取决于写法。"""
        from agents.surface_discovery import MAX_DELAY_SECONDS, MIN_DELAY_SECONDS

        for rate, interval in ((10_000, MIN_DELAY_SECONDS), (0.000_001, MAX_DELAY_SECONDS)):
            with self.subTest(rate=rate):
                self.assertEqual(
                    self._scope(program="p", authorization="a", allowed_hosts=["x.com"],
                                rate_limit={"min_interval_seconds": interval}).delay_seconds,
                    self._scope(program="p", authorization="a", allowed_hosts=["x.com"],
                                requests_per_second=rate).delay_seconds,
                )

    def test_an_unparseable_rate_falls_back_instead_of_guessing(self) -> None:
        """``"fast"`` 不是速率。读不懂就退回老的读法,而不是当成 0 或当成无限快。"""
        scope = self._scope(program="p", authorization="a", allowed_hosts=["x.com"],
                            requests_per_second="fast", surface_delay_seconds=1.5)
        self.assertEqual(1.5, scope.delay_seconds)

    def test_a_zero_rate_is_not_a_licence_to_flood(self) -> None:
        """0 是个明显写错的值。它必须退回保守默认,而不是变成"不限速"。"""
        scope = self._scope(program="p", authorization="a", allowed_hosts=["x.com"],
                            requests_per_second=0)
        self.assertGreater(scope.delay_seconds, 0)

    def test_a_scope_file_without_the_field_behaves_exactly_as_before(self) -> None:
        """老文件没这一维,读出来的节奏必须一个字节都不变。"""
        legacy = self._scope(program="p", authorization="a", allowed_hosts=["x.com"],
                             rate_limit={"min_interval_seconds": 0.5})
        self.assertEqual(0.5, legacy.delay_seconds)
        self.assertEqual(0.4, self._scope(program="p", authorization="a",
                                          allowed_hosts=["x.com"]).delay_seconds)

    def test_the_two_units_are_the_same_promise(self) -> None:
        """``requests_per_second`` 是 ``delay_seconds`` 的另一种写法,不是第二个真相。"""
        scope = self._scope(program="p", authorization="a", allowed_hosts=["x.com"],
                            requests_per_second=2.5)
        self.assertAlmostEqual(1 / scope.delay_seconds, scope.requests_per_second, places=6)


class RequestMethodTests(unittest.TestCase):
    """方法真的传到了线上 —— 这件事只有服务器那一侧看得见。

    修掉的谎:HEAD 以前是"校验通过之后按 GET 执行"。审计行如果写 GET 而实际发的
    是别的动词(或者反过来),那条审计比没有审计更糟。
    """

    seen: list = []

    @classmethod
    def setUpClass(cls):
        import os
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        # 这台机器上 HTTP_PROXY 指向本地代理,而代理会改写方法/吞掉 HEAD 的语义。
        # 这几条测的是我们的传输层,所以必须直连回环。
        os.environ["NO_PROXY"] = "127.0.0.1"
        os.environ["no_proxy"] = "127.0.0.1"

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _record(self):  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                payload_in = self.rfile.read(length) if length else b""
                RequestMethodTests.seen.append(
                    (self.command, self.path, payload_in.decode("utf-8", "replace"),
                     self.headers.get("Content-Type") or ""))
                out = b'{"ok": true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(out)

            do_GET = do_HEAD = do_POST = do_PUT = _record

            def log_message(self, *args) -> None:
                pass

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self) -> None:
        RequestMethodTests.seen.clear()

    def _url(self, path: str = "/x") -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def test_head_reaches_the_server_as_head(self) -> None:
        from agents.surface_discovery import _request_text

        status, body, _headers = _request_text("HEAD", self._url("/admin"), timeout=5.0)
        self.assertEqual(200, status)
        self.assertEqual("HEAD", self.seen[-1][0])
        # HEAD 没有正文;以前那条"按 GET 执行"会带回一个 body,顺带暴露审计是假的。
        self.assertEqual("", body)

    def test_post_carries_the_body_and_the_content_type(self) -> None:
        from agents.surface_discovery import _request_text

        status, body, _headers = _request_text(
            "POST", self._url("/api/query"), timeout=5.0,
            body=b'{"q": 1}', content_type="application/json")
        self.assertEqual(200, status)
        self.assertIn("ok", body)
        method, _path, payload, content_type = self.seen[-1]
        self.assertEqual("POST", method)
        self.assertEqual('{"q": 1}', payload)
        self.assertEqual("application/json", content_type)

    def test_get_goes_through_the_same_door(self) -> None:
        """``_fetch_text`` 现在只是 GET 的薄包装 —— 一个出口,不是两个。"""
        from agents.surface_discovery import _fetch_text

        _fetch_text(self._url("/"), timeout=5.0)
        self.assertEqual("GET", self.seen[-1][0])

    def test_a_body_without_a_content_type_gets_the_form_default(self) -> None:
        from agents.surface_discovery import _request_text

        _request_text("POST", self._url("/form"), timeout=5.0, body=b"a=1")
        self.assertEqual("application/x-www-form-urlencoded", self.seen[-1][3])


if __name__ == "__main__":
    unittest.main()
