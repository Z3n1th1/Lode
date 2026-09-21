"""Tests for core.action_admission — the fifth gate, and the red lines it encodes.

The red lines this file pins (ByteSRC《测试红线10条》): 禁止任何增删改数据/配置的"写"操作;
高风险操作必须经人工判断后执行. Since ``guardrails.tools.human_gate`` is hard-blocked and no
local path can approve anything, "needs a human" has to mean "refused" — that equivalence
is the single most important thing here.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT))

from core import action_admission as A


def _admit(method, url, body="", content_type=""):
    return A.admit(method=method, url=url, body=body, content_type=content_type)


class DestructiveMethodTests(unittest.TestCase):
    def test_delete_is_refused_outright(self):
        verdict = _admit("DELETE", "https://h.example/api/users/1")
        self.assertFalse(verdict.allowed)
        self.assertEqual(A.DESTRUCTIVE_METHOD, verdict.reason)

    def test_delete_is_not_a_declarable_value(self):
        from agents.surface_discovery import _METHOD_VOCABULARY

        self.assertNotIn("DELETE", _METHOD_VOCABULARY)


class ReadPathTests(unittest.TestCase):
    """读取是本产品的全部功能,所以这一档要稳;唯一收紧的是改状态形状。"""

    def test_a_plain_read_is_allowed(self):
        self.assertTrue(_admit("GET", "https://h.example/api/orders?page=2").allowed)
        self.assertTrue(_admit("HEAD", "https://h.example/api/orders").allowed)

    def test_a_state_changing_url_is_refused_even_for_get(self):
        """``GET /logout`` 就是一次写操作,载着它的动词是 GET 不影响这个判断。"""
        for url in ("https://h.example/api/deleteUser",
                    "https://h.example/logout",
                    "https://h.example/api/UpdateStatus",
                    "https://h.example/api/DropDownOptions"):
            with self.subTest(url=url):
                verdict = _admit("GET", url)
                self.assertFalse(verdict.allowed)
                self.assertEqual("state_changing_endpoint", verdict.reason)

    def test_an_unknown_selector_is_refused_on_the_read_path(self):
        verdict = _admit("GET", "https://h.example/api/x?action=ping")
        self.assertEqual("unknown_operation_selector", verdict.reason)

    def test_a_read_selector_is_fine_on_the_read_path(self):
        self.assertTrue(_admit("GET", "https://h.example/api/x?action=query").allowed)

    def test_the_scanner_is_not_applied_to_reads(self):
        """``GET ?url=https://…`` / ``/api/orders`` 是本产品的核心读法,不能被扫成"外联"。"""
        for url in ("https://h.example/api/fetch?url=https://internal.example/",
                    "https://h.example/api/orders",
                    "https://h.example/api/settings"):
            with self.subTest(url=url):
                self.assertTrue(_admit("GET", url).allowed, url)


class ProbeTierTests(unittest.TestCase):
    def test_options_is_allowed_without_a_body(self):
        verdict = _admit("OPTIONS", "https://h.example/openidm/info/version")
        self.assertTrue(verdict.allowed)
        self.assertEqual("options", verdict.detail.get("proof"))

    def test_options_with_a_body_is_refused(self):
        verdict = _admit("OPTIONS", "https://h.example/api/x", body="a=1")
        self.assertEqual(A.NOT_PROVEN, verdict.reason)

    def test_a_declared_read_selector_opens_the_probe_tier(self):
        verdict = _admit("POST", "https://h.example/api/x?action=query",
                         body="a=1", content_type="application/x-www-form-urlencoded")
        self.assertTrue(verdict.allowed)
        self.assertEqual("read_selector", verdict.detail.get("proof"))

    def test_a_graphql_query_is_allowed(self):
        verdict = _admit("POST", "https://h.example/api/graphql",
                         body='{"query": "{ __typename }"}', content_type="application/json")
        self.assertTrue(verdict.allowed)
        self.assertEqual("graphql_query", verdict.detail.get("proof"))

    def test_a_graphql_mutation_is_refused(self):
        for body in ('{"query": "mutation { deleteUser(id: 1) { ok } }"}',
                     '{"query": "subscription { onEvent }"}',
                     '{"query": "{ x }", "operationName": "Q", "extra": 1}',
                     '{"variables": {}}'):
            with self.subTest(body=body):
                verdict = _admit("POST", "https://h.example/api/graphql",
                                 body=body, content_type="application/json")
                self.assertFalse(verdict.allowed, body)

    def test_an_unproven_post_is_refused_with_or_without_a_body(self):
        """空 body 不是证明:``POST /logout`` 和 ``POST /api/items`` 都没有 body。"""
        for body in ("", '{"id": 1}', '{"q": 1}'):
            with self.subTest(body=body):
                verdict = _admit("POST", "https://h.example/api/items",
                                 body=body, content_type="application/json")
                self.assertEqual(A.NOT_PROVEN, verdict.reason)

    def test_put_and_patch_are_refused_by_semantics(self):
        for method in ("PUT", "PATCH"):
            with self.subTest(method=method):
                verdict = _admit(method, "https://h.example/api/users/1",
                                 body='{"name": "x"}', content_type="application/json")
                self.assertFalse(verdict.allowed)
                self.assertEqual("mutating_request_refused:update_semantics", verdict.reason)

    def test_a_method_outside_the_probe_tier_is_refused(self):
        verdict = _admit("TRACE", "https://h.example/api/users")
        self.assertEqual(A.NOT_IN_PROBE_TIER, verdict.reason)


class SensitiveSurfaceTests(unittest.TestCase):
    """读一个敏感面**不是**它被拒的理由。

    真机实测（2026-09-21, login-dev.nba.com）暴露过一次：把 ``value_scanners`` 的信号
    当成硬闸门，于是 ``OPTIONS /openidm/config/managed``（RFC 安全、零副作用）因为 URL 里
    有 ``config`` 被拒、``POST /openidm/managed/user?_action=validateGoto``（读选择器）因为
    URL 里有 ``user`` 被拒 —— 探测档在真目标上等于没有。

    那三个信号（``privilege_or_credential`` / ``cleanup_keyword`` / ``shared_state``）回答的
    是"**改**这个面危不危险"，不是"这个请求会不会改东西"。``guardrails.action_policy.refine``
    也只对 create/modify/other 查它们。
    """

    def test_options_on_a_config_surface_is_allowed(self):
        verdict = _admit("OPTIONS", "https://h.example/openidm/config/managed")
        self.assertTrue(verdict.allowed, verdict.reason)

    def test_options_on_a_user_admin_surface_is_allowed(self):
        for url in ("https://h.example/api/users", "https://h.example/openidm/managed/user",
                    "https://h.example/admin/roles", "https://h.example/api/orders",
                    "https://h.example/api/settings"):
            with self.subTest(url=url):
                self.assertTrue(_admit("OPTIONS", url).allowed, url)

    def test_a_proven_read_on_a_sensitive_surface_is_allowed(self):
        for url in ("https://h.example/api/users?action=query",
                    "https://h.example/api/orders?action=list",
                    "https://h.example/api/v2/group?op=search",
                    "https://h.example/api/users?_action=query"):
            with self.subTest(url=url):
                verdict = _admit("POST", url, body='{"q":1}', content_type="application/json")
                self.assertTrue(verdict.allowed, f"{url} -> {verdict.reason}")

    def test_an_unrecognised_selector_value_is_refused_not_guessed(self):
        """deny-by-default 的另一面:认不出的选择器值不当成读。

        ``?_action=validateGoto`` 是 ForgeRock 常见的读操作,但 "validateGoto" 不是
        我们词汇表里的读词 —— 光看名字证明不了它是读,所以拒。这条如实记下来,免得
        以后有人把它当 bug "修"成放行。
        """
        verdict = _admit("POST", "https://h.example/openidm/managed/user?_action=validateGoto",
                         body='{"goto":"/x"}', content_type="application/json")
        self.assertFalse(verdict.allowed)

    def test_an_underscore_selector_cannot_smuggle_a_write_through_get(self):
        """``_action`` 曾经不在选择器键名里 —— ``GET ?_action=patch`` 因此漏得过。"""
        verdict = _admit("GET", "https://h.example/api/x?_action=patch")
        self.assertFalse(verdict.allowed)
        self.assertEqual("unknown_operation_selector", verdict.reason)

    def test_an_unproven_request_on_a_sensitive_surface_says_which_signal(self):
        """拒绝理由要能指路 —— "它碰了一个敏感面"和"形状不是读"是两回事。"""
        verdict = _admit("POST", "https://h.example/api/users", body='{"role":"x"}',
                         content_type="application/json")
        self.assertFalse(verdict.allowed)
        self.assertTrue(verdict.reason.startswith(A.NOT_PROVEN), verdict.reason)

    def test_server_side_egress_stays_a_hard_gate_even_for_a_proven_read(self):
        """这条不同:外联落在**第三方**身上,而 scope 闸门看不见它(红线 8)。"""
        verdict = _admit("POST", "https://h.example/api/fetch?action=query",
                         body='{"target": "https://internal.example/"}',
                         content_type="application/json")
        self.assertFalse(verdict.allowed)
        self.assertEqual("mutating_request_refused:server_side_egress", verdict.reason)


class ClassifierSeesTheBodyTests(unittest.TestCase):
    """不给分类器解析后的容器,body 覆盖就是假的 —— ``action_kind`` 读不出 ``str``。"""

    def test_a_selector_hidden_in_a_form_body_is_caught(self):
        verdict = _admit("POST", "https://h.example/api/x", body="action=delete",
                         content_type="application/x-www-form-urlencoded")
        self.assertFalse(verdict.allowed)
        self.assertEqual("mutating_request_refused:delete", verdict.reason)

    def test_a_percent_encoded_selector_in_a_form_body_is_caught(self):
        verdict = _admit("POST", "https://h.example/api/x", body="action=%64elete",
                         content_type="application/x-www-form-urlencoded")
        self.assertFalse(verdict.allowed, "编码过的 delete 不能藏住")

    def test_a_selector_in_a_json_body_is_caught(self):
        verdict = _admit("POST", "https://h.example/api/x", body='{"operation": "delete"}',
                         content_type="application/json")
        self.assertFalse(verdict.allowed)

    def test_a_server_side_callback_is_caught(self):
        verdict = _admit("POST", "https://h.example/api/x",
                         body='{"callback_url": "https://evil.example/"}',
                         content_type="application/json")
        self.assertEqual("mutating_request_refused:server_side_egress", verdict.reason)

    def test_an_operation_selector_in_the_url_still_wins(self):
        verdict = _admit("POST", "https://h.example/api/x?action=sendEmail", body="to=a@b.c")
        self.assertEqual("unknown_operation_selector", verdict.reason)


class FailClosedTests(unittest.TestCase):
    """分类器不可用时:探测档关闭,读路径照常,整个运行不中断。"""

    def test_the_probe_tier_closes_when_the_classifier_is_missing(self):
        with patch.object(A, "_guardrails", return_value=(None, None, "ImportError: boom")):
            for method in ("POST", "PUT", "PATCH", "OPTIONS"):
                with self.subTest(method=method):
                    verdict = _admit(method, "https://h.example/api/x?action=query")
                    self.assertFalse(verdict.allowed)
                    self.assertEqual(A.CLASSIFIER_UNAVAILABLE, verdict.reason)
                    self.assertIn("ImportError", verdict.detail.get("error", ""))

    def test_reads_keep_working_when_the_classifier_is_missing(self):
        with patch.object(A, "_guardrails", return_value=(None, None, "ImportError: boom")):
            self.assertTrue(_admit("GET", "https://h.example/api/orders").allowed)

    def test_a_broken_classifier_does_not_open_the_gate(self):
        class Boom:
            @staticmethod
            def action_kind(card):
                raise RuntimeError("classifier broke")

        with patch.object(A, "_guardrails", return_value=(Boom, Boom, "")):
            verdict = _admit("POST", "https://h.example/api/x?action=query")
            self.assertFalse(verdict.allowed)
            self.assertEqual(A.CLASSIFIER_UNAVAILABLE, verdict.reason)


class BudgetOfTruthTests(unittest.TestCase):
    def test_the_advertised_methods_are_the_ones_that_can_be_sent(self):
        """提示词不能广告一个闸门恒拒的动词 —— PUT/PATCH 在声明里,不在可发集合里。"""
        self.assertIn("GET", A.ADMISSIBLE_METHODS)
        self.assertIn("HEAD", A.ADMISSIBLE_METHODS)
        self.assertIn("OPTIONS", A.ADMISSIBLE_METHODS)
        self.assertIn("POST", A.ADMISSIBLE_METHODS)
        self.assertNotIn("PUT", A.ADMISSIBLE_METHODS)
        self.assertNotIn("PATCH", A.ADMISSIBLE_METHODS)
        self.assertNotIn("DELETE", A.ADMISSIBLE_METHODS)

    def test_the_advertised_set_matches_a_declared_scope(self):
        from agents.surface_discovery import _ADMISSIBLE_METHODS as from_module

        self.assertEqual(A.ADMISSIBLE_METHODS, from_module)


if __name__ == "__main__":
    unittest.main()
