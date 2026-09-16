"""Tests for core.targets — the target parser and the one SSRF/authorization gate.

This module decides what counts as the *authorized scope*, so its classification
table is a contract: "两段是域名、三段是主机" is the difference between scanning a
registrable domain and scanning one host, and it has to be readable off the
written form (``*.a.b.x.com`` when you mean the whole thing).
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "core"))

from core import targets  # noqa: E402


class GateTests(unittest.TestCase):
    """``public_target_reason`` is the only gate: "" means allowed."""

    def test_public_http_targets_pass(self) -> None:
        for raw in ("example.com", "https://example.com/a?b=1", "https://a.b.example.com:8443/x"):
            with self.subTest(raw=raw):
                self.assertEqual("", targets.public_target_reason(raw))

    def test_private_and_loopback_are_refused(self) -> None:
        refused = {
            "http://127.0.0.1/": "non_public_ip",
            "http://10.0.0.5/": "non_public_ip",
            "http://169.254.169.254/latest/meta-data/": "non_public_ip",
            "http://[::1]/": "non_public_ip",
            "http://localhost/": "localhost",
            "http://foo.localhost/": "localhost",
        }
        for raw, reason in refused.items():
            with self.subTest(raw=raw):
                self.assertEqual(reason, targets.public_target_reason(raw))

    def test_credentials_and_bad_ports_never_get_persisted(self) -> None:
        self.assertEqual("embedded_credentials", targets.public_target_reason("https://u:p@example.com/"))
        self.assertEqual("bad_port", targets.public_target_reason("https://example.com:bad/"))
        self.assertEqual("scheme_not_http", targets.public_target_reason("file:///etc/passwd"))

    def test_a_non_ascii_host_is_refused_rather_than_guessed(self) -> None:
        """No punycode conversion happens anywhere, so an IDN must be written as one.

        放行非 ASCII 还有更实际的后果:``http://10.0.0.5做`` 这种粘了中文的地址
        ``ipaddress`` 认不出来、又"有个点",于是私网判定整个失效。
        """
        self.assertEqual("not_a_public_host", targets.public_target_reason("http://10.0.0.5做/"))
        self.assertEqual("not_a_public_host", targets.public_target_reason("http://例子.测试/"))
        self.assertEqual("", targets.public_target_reason("http://xn--fsqu00a.xn--0zwm56d/"))


class ClassificationTests(unittest.TestCase):
    def test_two_labels_is_an_apex_three_is_a_host(self) -> None:
        self.assertEqual(("example.com",), targets.split_targets("example.com").domains)
        self.assertEqual((), targets.split_targets("example.com").hosts)
        self.assertEqual(("www.example.com",), targets.split_targets("www.example.com").hosts)
        self.assertEqual((), targets.split_targets("www.example.com").domains)

    def test_a_two_label_suffix_does_not_make_an_apex_out_of_a_host(self) -> None:
        self.assertEqual(("b.co.uk",), targets.split_targets("b.co.uk").domains)
        self.assertEqual(("a.b.co.uk",), targets.split_targets("a.b.co.uk").hosts)

    def test_a_wildcard_is_the_way_to_widen(self) -> None:
        split = targets.split_targets("*.a.b.co.uk")
        self.assertEqual(("a.b.co.uk",), split.domains)
        self.assertEqual((), split.hosts)

    def test_an_entrypoint_keeps_its_scheme_port_and_query(self) -> None:
        split = targets.split_targets("http://x.example.com:8080/p?q=1#frag")
        self.assertEqual(("http://x.example.com:8080/p?q=1",), split.entrypoints)

    def test_a_url_glued_to_chinese_stops_at_the_chinese(self) -> None:
        split = targets.split_targets("对https://rei.com做信息收集")
        self.assertEqual(("https://rei.com/",), split.entrypoints)
        # first_url 给的是没归一化的原文(只剥装饰),所以它没有空路径那个斜杠
        self.assertEqual("https://rei.com", targets.first_url("对https://rei.com做信息收集"))

    def test_prose_is_not_reported_as_rejected_targets(self) -> None:
        """"把一整页说明拆出来的一堆词" 逐条报拒绝,只会把确认单淹掉。"""
        split = targets.split_targets("下面这段话提到了内部约定和某个流程,没有别的了")
        self.assertEqual((), split.rejected)
        self.assertEqual((), split.entrypoints + split.domains + split.hosts)

    def test_a_version_string_is_not_a_host(self) -> None:
        split = targets.split_targets("v1.2.3")
        self.assertEqual((), split.domains + split.hosts)

    def test_an_asset_covered_by_a_domain_in_the_same_list_is_merged(self) -> None:
        """同一个清单里 rei.com 和 www.rei.com 是一份授权,不是一个资产扫两遍。"""
        split = targets.split_targets("rei.com www.rei.com")
        self.assertEqual(("rei.com",), split.domains)
        self.assertEqual((), split.hosts)
        self.assertIn(("www.rei.com", "covered_by_domain"), split.rejected)

    def test_the_token_count_includes_prose(self) -> None:
        """调用方靠这个数判"清单还是说明文字",所以散文也得算进去。"""
        self.assertEqual(3, targets.split_targets("扫 x.example.com、y.example.com").tokens)
        self.assertEqual(1, targets.split_targets("https://single.example.com/").tokens)


class AssetTests(unittest.TestCase):
    def test_entrypoints_come_first_then_domains_then_hosts(self) -> None:
        split = targets.split_targets("z.example.com https://a.example.com/ b.example.com")
        self.assertEqual(["https://a.example.com/", "https://b.example.com/", "https://z.example.com/"],
                         [asset.display for asset in targets.assets(split)])

    def test_scope_lists_are_the_three_columns(self) -> None:
        # 三个目标各自属于不同的注册域,否则会被覆盖合并吃掉(见下一个用例)
        split = targets.split_targets("https://a.example.com/ example.org c.d.example.net")
        self.assertEqual({"entrypoints": ["https://a.example.com/"],
                          "domains": ["example.org"],
                          "hosts": ["c.d.example.net"]},
                         targets.scope_lists(split))


if __name__ == "__main__":
    unittest.main()
