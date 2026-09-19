"""Scope construction for targets typed into the console conversation.

This is a safety boundary, not a routing detail: it decides which hosts a run is
allowed to touch.  It had no test at all, which is how it kept widening a typed
URL to its registrable domain while ``allowed_domains`` matched descendants — on
a closed-scope program that silently authorises hosts the program excludes.
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "core"))

from console import jobs  # noqa: E402


class _Job:
    """Just enough of a JobRecord for the scope builder."""

    def __init__(self, target: str, payload: dict | None = None) -> None:
        self.target = target
        self.payload = payload or {}


def _scope(target: str, payload: dict | None = None):
    return jobs._typed_target_scope(_Job(target, payload), run_id="r1", target_url=target)


class TypedTargetScopeTests(unittest.TestCase):
    def test_a_typed_url_authorises_only_that_host(self) -> None:
        """粘一个 URL 不能把整个域打开。

        ``allowed_domains`` 是后代匹配,所以以前 ``www.nba.com`` 会自动带出
        ``nba.com`` —— 而程序明确排除的 ``cms.`` / ``payment.`` /
        ``login-sandbox.`` / ``arcade.`` 全在这个域下面。
        """
        scope = _scope("https://www.nba.com/")
        self.assertTrue(scope.check_url("https://www.nba.com/")[0])
        for host in ("cms.nba.com", "payment.nba.com", "login-sandbox.nba.com",
                     "arcade.nba.com", "mediacentral.nba.com", "api.nba.com"):
            with self.subTest(host=host):
                allowed, reason = scope.check_url(f"https://{host}/")
                self.assertFalse(allowed, f"{host} 不该被一个 www 的粘贴授权")
                self.assertEqual("host_not_in_scope", reason)
        self.assertEqual((), scope.allowed_domains)

    def test_a_sibling_host_is_not_authorised_either(self) -> None:
        scope = _scope("https://api.nba.com/")
        self.assertTrue(scope.check_url("https://api.nba.com/")[0])
        self.assertFalse(scope.check_url("https://api-qa.nba.com/")[0])

    def test_naming_hosts_explicitly_is_how_you_reach_further(self) -> None:
        """要跨主机就得显式点名 —— 而不是靠后缀自动带出来。"""
        scope = _scope("https://www.nba.com/",
                       {"allowed_hosts": ["api.nba.com", "stats.nba.com"]})
        self.assertTrue(scope.check_url("https://api.nba.com/")[0])
        self.assertTrue(scope.check_url("https://stats.nba.com/")[0])
        self.assertTrue(scope.check_url("https://www.nba.com/")[0])
        self.assertFalse(scope.check_url("https://cms.nba.com/")[0])

    def test_the_payloads_exclusion_list_is_carried_through(self) -> None:
        scope = _scope("https://api.nba.com/", {"forbidden_hosts": ["api.nba.com"]})
        allowed, reason = scope.check_url("https://api.nba.com/")
        self.assertFalse(allowed)
        self.assertEqual("forbidden_host", reason)

    def test_the_delay_can_be_raised_from_outside(self) -> None:
        """写死 0.5s 在两个 worker 下是 4 req/s,超过程序写明的 3 req/s 上限。"""
        self.assertEqual(1.0, _scope("https://a.example.com/", {"delay_seconds": 1.0}).delay_seconds)
        with patch.dict(os.environ, {"LODE_SURFACE_DELAY_SECONDS": "1.5"}):
            self.assertEqual(1.5, _scope("https://a.example.com/").delay_seconds)
        # 没给就用老默认,别把既有调用方的行为改了
        self.assertEqual(0.5, _scope("https://a.example.com/").delay_seconds)
        # 荒谬的值被夹住,而不是原样送进 sleep
        self.assertEqual(0.1, _scope("https://a.example.com/", {"delay_seconds": 0}).delay_seconds)

    def test_the_scope_still_passes_authorization(self) -> None:
        _scope("https://a.example.com/").require_authorization()


class SurfaceScanProducerTests(unittest.TestCase):
    """``surface_scan`` had a handler and a renderer but no producer — nothing in
    the product could ever create one, so the cheap half of a hunt was unreachable."""

    def test_the_kind_is_wired_to_a_handler(self) -> None:
        self.assertIn("surface_scan", jobs.HANDLERS)

    def test_its_scope_is_the_named_target_not_nothing(self) -> None:
        """它以前自建空 scope,``require_authorization`` 会直接抛 surface_scope_required。"""
        scope = _scope("https://a.example.com/")
        scope.require_authorization()
        self.assertTrue(scope.check_url("https://a.example.com/")[0])


if __name__ == "__main__":
    unittest.main()
