"""授权文档的判定与解析 —— 三个入口(粘贴/上传/监听目录)共用的那一处。

这里钉的是两件事:什么算"一份授权文档",以及一份文档到底授权了什么。

第一件事必须保守。认不出来的代价是操作员多看一句话;认错的代价是把一段**举例**
当成一次授权。
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "core"))

from agents.scope_document import (  # noqa: E402
    DEFAULT_MAX_FANOUT, HARD_MAX_FANOUT, ScopeDocumentError,
    looks_like_scope_document, max_fanout_for, parse_scope_document,
)


def _document(**overrides) -> dict:
    doc = {
        "program": "nba-public",
        "authorization": "HackerOne managed program, closed scope",
        "allowed_hosts": ["api.nba.com", "cdn.nba.com"],
        "forbidden_hosts": ["cms.nba.com"],
        "rate_limit": {"requests_per_second": 3},
        "allowed_methods": ["POST"],
        "allow_request_body": True,
    }
    doc.update(overrides)
    return doc


class DetectionTests(unittest.TestCase):
    def test_a_pasted_document_is_recognised(self) -> None:
        self.assertIsNotNone(looks_like_scope_document(json.dumps(_document())))

    def test_a_whole_text_code_fence_is_unwrapped(self) -> None:
        """操作员从聊天里复制出来的东西几乎总是被围栏包着。"""
        for payload in (json.dumps(_document(), indent=2), json.dumps(_document())):
            with self.subTest(payload=payload[:20]):
                fenced = f"```json\n{payload}\n```"
                self.assertIsNotNone(looks_like_scope_document(fenced))
                self.assertEqual(_document(), looks_like_scope_document(fenced))
        self.assertIsNotNone(looks_like_scope_document(f"```\n{json.dumps(_document())}\n```"))

    def test_prose_around_the_json_is_not_a_document(self) -> None:
        """夹在句子里的一段 JSON 是一句**关于**文档的话,不是一份文档。

        放宽这一条,就等于让聊天里引用的例子直接获得授权。
        """
        text = f"这是我抄来的配置,你看看:{json.dumps(_document())}"
        self.assertIsNone(looks_like_scope_document(text))

    def test_an_unterminated_fence_is_not_a_document(self) -> None:
        self.assertIsNone(looks_like_scope_document(f"```json\n{json.dumps(_document())}"))

    def test_a_truncated_paste_is_not_a_document(self) -> None:
        """截断的 JSON 解析不了 —— 这正是不该硬猜的地方(NBA 那次就是断在 "login-qa.n)。"""
        self.assertIsNone(looks_like_scope_document(json.dumps(_document())[:-25]))

    def test_other_json_shapes_do_not_qualify(self) -> None:
        cases = {
            "不是 JSON": "hello",
            "JSON 数组": json.dumps([_document()]),
            "TargetCard": json.dumps({"schema": "TargetCard/v1", "authorization": "a",
                                      "allowed_hosts": ["a.com"]}),
            "intake 载荷": json.dumps({"authorization": "a", "allowed_hosts": ["a.com"],
                                       "target_url": "https://a.com/"}),
            "没有 authorization": json.dumps({"allowed_hosts": ["a.com"]}),
            "没有主机类键": json.dumps({"authorization": "a", "program": "p"}),
            "只有 data 外壳": json.dumps({"data": _document()}),
        }
        for name, text in cases.items():
            with self.subTest(case=name):
                self.assertIsNone(looks_like_scope_document(text))

    def test_the_nested_scope_shape_is_recognised_too(self) -> None:
        """``from_mapping`` 认嵌套的 ``scope``,判定不能比它窄。"""
        text = json.dumps({"schema": "TargetCard/v1", "authorization": "a"})
        self.assertIsNone(looks_like_scope_document(text))
        nested = {"authorization": "a", "scope": {"allowed_hosts": ["a.com"]}}
        self.assertIsNotNone(looks_like_scope_document(json.dumps(nested)))
        self.assertEqual(("a.com",), parse_scope_document(nested).hosts)


class ParsingTests(unittest.TestCase):
    def _parse(self, **overrides):
        return parse_scope_document(_document(**overrides))

    def test_only_exact_hosts_become_targets(self) -> None:
        self.assertEqual(("api.nba.com", "cdn.nba.com"), self._parse().hosts)

    def test_document_order_and_dedup_are_kept(self) -> None:
        """顺序是操作员的优先级,不该被排序掉;重复只是重复。"""
        parsed = self._parse(allowed_hosts=["z.nba.com", "a.nba.com", "z.nba.com"])
        self.assertEqual(("z.nba.com", "a.nba.com"), parsed.hosts)

    def test_a_seed_url_contributes_its_host_never_its_domain(self) -> None:
        """seed_urls 里写的是某个主机上的一条路径。

        把它放宽到可注册域,就是把"这个站"换成"整个域" —— 9045ee3 那个事故的形状。
        """
        parsed = self._parse(allowed_hosts=["api.nba.com"],
                             seed_urls=["https://www.nba.com/some/path", "cdn.nba.com"])
        self.assertEqual(("api.nba.com", "www.nba.com", "cdn.nba.com"), parsed.hosts)
        self.assertNotIn("nba.com", parsed.hosts)

    def test_a_domain_pattern_is_refused_and_named(self) -> None:
        """域模式授权的是整片子域,而不是操作员逐一看过的那几台主机。"""
        with self.assertRaises(ScopeDocumentError) as ctx:
            parse_scope_document({"authorization": "a", "allowed_domains": ["nba.com", "wnba.com"]})
        self.assertEqual("scope_document_domains_not_allowed", ctx.exception.reason)
        self.assertIn("nba.com", ctx.exception.detail)
        self.assertIn("wnba.com", ctx.exception.detail)

    def test_a_wildcard_host_is_refused_like_a_domain_pattern(self) -> None:
        """``*.nba.com`` 和 ``allowed_domains`` 是同一件事的两种写法。

        放它过去,等于用一个更不起眼的拼法绕开上面那条拒绝。
        """
        parsed = self._parse(allowed_hosts=["*.nba.com", "api.nba.com"])
        self.assertEqual(("api.nba.com",), parsed.hosts)
        self.assertEqual((("*.nba.com", "scope_document_wildcard_not_allowed"),), parsed.rejected)

    def test_non_public_hosts_are_dropped_and_reported(self) -> None:
        """闸门是 targets.py 那一道,不是这里新写的一道。"""
        parsed = self._parse(allowed_hosts=["api.nba.com", "localhost", "10.0.0.5"])
        self.assertEqual(("api.nba.com",), parsed.hosts)
        self.assertEqual((("localhost", "localhost"), ("10.0.0.5", "non_public_ip")), parsed.rejected)

    def test_a_document_with_no_usable_host_is_refused(self) -> None:
        with self.assertRaises(ScopeDocumentError) as ctx:
            parse_scope_document({"authorization": "a", "allowed_hosts": ["localhost"]})
        self.assertEqual("scope_document_no_hosts", ctx.exception.reason)

    def test_an_empty_authorization_is_refused_with_the_canonical_code(self) -> None:
        """不另造一套词汇:原因码和 ``require_authorization`` 逐字相同。"""
        with self.assertRaises(ScopeDocumentError) as ctx:
            parse_scope_document(_document(authorization=""))
        self.assertEqual("surface_authorization_required", ctx.exception.reason)

    def test_the_capability_and_the_rate_are_inherited_from_the_one_loader(self) -> None:
        """文档说的"能做什么"和"多快"必须活着走到 scope 上。

        这条是防漂移测试的轻量版:Console 以前手工拼 scope,能力维度就是在这里丢的。
        """
        parsed = self._parse()
        self.assertEqual(("GET", "HEAD", "POST"), parsed.scope.allowed_methods)
        self.assertTrue(parsed.scope.allow_request_body)
        self.assertAlmostEqual(3.0, parsed.scope.requests_per_second, places=6)
        self.assertEqual(("cms.nba.com",), parsed.scope.forbidden)

    def test_the_verbatim_document_is_kept(self) -> None:
        """记录里要能放下原话 —— 事后审的人读的是程序写了什么,不是我们理解成什么。"""
        doc = _document()
        self.assertEqual(doc, parse_scope_document(doc).document)


class FanoutCapTests(unittest.TestCase):
    def test_the_default_is_thirty(self) -> None:
        self.assertEqual(30, DEFAULT_MAX_FANOUT)
        self.assertEqual(DEFAULT_MAX_FANOUT, max_fanout_for(_document()))

    def test_a_document_can_lower_its_own_cap(self) -> None:
        """程序文档里写了"别抬上限"的时候,那句话是授权的边界。"""
        self.assertEqual(4, max_fanout_for(_document(max_fanout=4)))
        self.assertEqual(4, parse_scope_document(_document(max_fanout=4)).max_fanout)

    def test_a_nested_cap_is_read_too(self) -> None:
        doc = {"authorization": "a", "scope": {"allowed_hosts": ["a.com"], "max_fanout": 2}}
        self.assertEqual(2, max_fanout_for(doc))

    def test_the_cap_cannot_exceed_the_asset_gate(self) -> None:
        """超过 targets.py 的资产上限,文档里就有一部分主机根本没走过那道闸门。"""
        self.assertEqual(HARD_MAX_FANOUT, max_fanout_for(_document(max_fanout=9999)))

    def test_a_zero_or_unreadable_cap_falls_back_instead_of_upward(self) -> None:
        """读不懂就退回默认,不猜一个更大的数 —— 这个数是往上走的风险。"""
        for raw in ("many", "", None, 0, -5):
            with self.subTest(raw=raw):
                self.assertGreaterEqual(max_fanout_for(_document(max_fanout=raw)), 1)
                self.assertLessEqual(max_fanout_for(_document(max_fanout=raw)), DEFAULT_MAX_FANOUT)


if __name__ == "__main__":
    unittest.main()
