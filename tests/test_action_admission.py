"""Tests for core.action_admission — the fifth gate, and the red lines it encodes.

The red lines this file pins (ByteSRC《测试红线10条》): 禁止删除/拖库/改已有数据;
查询与 INSERT canary 可做; 高风险操作必须经人工判断后执行. Since
``guardrails.tools.human_gate`` is hard-blocked and no local path can approve
anything, "needs a human" has to mean "refused" — that equivalence is the
single most important thing here.
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

    def test_read_body_operation_selectors_are_checked_on_get_too(self):
        for body, content_type in (
            ("action=delete", "application/x-www-form-urlencoded"),
            ("mode=truncate", "application/x-www-form-urlencoded"),
            ('{"operation":"remove"}', "application/json"),
            ('{"operation":"query","operation":"delete"}', "application/json"),
        ):
            with self.subTest(body=body):
                verdict = _admit("GET", "https://h.example/api/items", body, content_type)
                self.assertFalse(verdict.allowed)
                self.assertEqual("unknown_operation_selector", verdict.reason)

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

    def test_terminal_read_routes_can_prove_an_inspectable_post(self):
        for route in ("search", "_search", "query", "list", "lookup", "count"):
            with self.subTest(route=route):
                verdict = _admit("POST", f"https://h.example/api/{route}/",
                                 '{"q":"assets","page":1}', "application/json")
                self.assertTrue(verdict.allowed, verdict.reason)
                self.assertEqual("read_route", verdict.detail.get("proof"))

    def test_a_read_route_is_not_a_substring_or_a_destructive_suffix(self):
        for url in (
            "https://h.example/api/searchUsers",
            "https://h.example/api/search/delete",
            "https://h.example/api/search%2Fremove",
            "https://h.example/api/removeFromSearch",
            "https://h.example/api/search;truncate",
            "https://h.example/api/delete/search",
        ):
            with self.subTest(url=url):
                verdict = _admit("POST", url, '{"q":"x"}', "application/json")
                self.assertFalse(verdict.allowed, url)

    def test_a_read_route_does_not_override_body_operation_or_unknown_payloads(self):
        for body, content_type in (
            ('{"action":"delete","q":"x"}', "application/json"),
            ('{"action":"query","action":"delete"}', "application/json"),
            ("action=delete&q=x", "application/x-www-form-urlencoded"),
            ('{"q":"x"}', "application/octet-stream"),
            ('[{"query":"{ x }"}]', "application/json"),
        ):
            with self.subTest(body=body):
                verdict = _admit("POST", "https://h.example/api/search", body, content_type)
                self.assertFalse(verdict.allowed, verdict.reason)

    def test_a_read_route_allows_search_terms_that_contain_delete_words(self):
        verdict = _admit("POST", "https://h.example/api/search",
                         '{"q":"find delete documentation","filter":"docs"}',
                         "application/json")
        self.assertTrue(verdict.allowed, verdict.reason)

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

    def test_a_proven_read_may_carry_an_http_ssrf_existence_url(self):
        """SSRF 存在性就是让目标去取一个 URL；HTTP(S) 要放行。"""
        verdict = _admit("POST", "https://h.example/api/fetch?action=query",
                         body='{"target": "https://internal.example/"}',
                         content_type="application/json")
        self.assertTrue(verdict.allowed, verdict.reason)


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

    def test_a_server_side_callback_without_read_proof_is_still_unproven(self):
        """没有读证明的 POST 仍拒；理由是形状不是读，不是“外联”本身。"""
        verdict = _admit("POST", "https://h.example/api/x",
                         body='{"callback_url": "https://evil.example/"}',
                         content_type="application/json")
        self.assertFalse(verdict.allowed)
        self.assertTrue(verdict.reason.startswith(A.NOT_PROVEN), verdict.reason)

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


class HazardousPayloadTests(unittest.TestCase):
    """ByteSRC / JSRC / TSRC 红线落在 GET 上:动词是读不等于 payload 无害。

    ``value_scanners`` 仍然不能上读路径 —— ``GET ?url=https://internal.example/``
    和 ``GET /api/orders`` 必须继续放行。这一档扫的是 *payload*，不是 URL 形取值。
    """

    def test_boolean_sqli_stays_allowed(self):
        for url in ("https://h.example/item?id=1'",
                    "https://h.example/item?id=1'+AND+1=1--",
                    "https://h.example/item?id=1'+AND+1=2--"):
            with self.subTest(url=url):
                self.assertTrue(_admit("GET", url).allowed, url)

    def test_a_short_sleep_existence_probe_is_allowed(self):
        """测有没有注入可以发；短 SLEEP / WAITFOR / pg_sleep 是存在性证明。"""
        cases = (
            "https://h.example/item?id=1'+AND+SLEEP(5)--",
            "https://h.example/item?id=1';WAITFOR%20DELAY%20'0:0:5'--",
            "https://h.example/item?id=1'+AND+pg_sleep(3)--",
            "https://h.example/item?id=1%27%20AND%20SLEEP%285%29--",
        )
        for url in cases:
            with self.subTest(url=url):
                self.assertTrue(_admit("GET", url).allowed, url)

    def test_resource_exhaustion_is_refused(self):
        cases = (
            "https://h.example/item?id=1'+AND+BENCHMARK(5000000,SHA1(1))--",
            "https://h.example/item?id=1'+AND+SLEEP(30)--",
            "https://h.example/item?id=1';WAITFOR%20DELAY%20'0:1:0'--",
        )
        for url in cases:
            with self.subTest(url=url):
                verdict = _admit("GET", url)
                self.assertFalse(verdict.allowed, url)
                self.assertEqual(A.RESOURCE_EXHAUSTION, verdict.reason)

    def test_product_path_named_sleep_is_not_a_payload(self):
        self.assertTrue(_admit("GET", "https://h.example/api/sleep?id=1").allowed)

    def test_destructive_sql_is_refused(self):
        # Put the payload in the body so the URL-token gate (``delete``/``drop`` as
        # path words) does not steal the reason from the SQL scanner.
        verdict = _admit("GET", "https://h.example/item?id=1",
                         body="1'; DELETE FROM audit--")
        self.assertFalse(verdict.allowed)
        self.assertEqual(A.DESTRUCTIVE_SQL, verdict.reason)
        # ``drop`` is also a state-changing URL token; either reason is a hard refuse.
        drop = _admit("GET", "https://h.example/item?id=1';DROP%20TABLE%20users--")
        self.assertFalse(drop.allowed)

    def test_insert_canary_is_allowed(self):
        """新增测试垃圾数据不是删除，payload 闸门放行。"""
        self.assertTrue(_admit(
            "GET", "https://h.example/item?q=1'+INSERT+INTO+canary+VALUES(1)--").allowed)

    def test_update_set_is_refused(self):
        verdict = _admit("GET", "https://h.example/item?id=1",
                         body="1'; UPDATE users SET role=1--")
        self.assertFalse(verdict.allowed)
        self.assertEqual(A.DESTRUCTIVE_SQL, verdict.reason)

    def test_command_injection_existence_probes_are_allowed(self):
        """``id`` / ``whoami`` / ``echo`` / ``time`` / LFI passwd prove RCE or file read exists."""
        cases = (
            "https://h.example/run?q=whoami",
            "https://h.example/run?q=1;id",
            "https://h.example/run?q=1;time",
            "https://h.example/run?q=%24%28id%29",
            "https://h.example/run?q=echo%20LODE1",
            "https://h.example/file?path=../../etc/passwd",
            "https://h.example/run?q=system('id')",
            "https://h.example/run?q=system('time')",
        )
        for url in cases:
            with self.subTest(url=url):
                self.assertTrue(_admit("GET", url).allowed, url)

    def test_post_exploit_shells_are_refused(self):
        cases = (
            "https://h.example/run?q=/bin/bash",
            "https://h.example/run?q=bash+-i",
            "https://h.example/run?q=nc+-e+/bin/sh",
            "https://h.example/run?q=meterpreter",
            "https://h.example/run?q=%3C%3Fphp+eval($_GET[1]);",
            "https://h.example/run?q=cat+/etc/shadow",
            "https://h.example/run?q=system('rm+-rf+/')",
        )
        for url in cases:
            with self.subTest(url=url):
                verdict = _admit("GET", url)
                self.assertFalse(verdict.allowed, url)
                self.assertEqual(A.SHELL_OR_WEBSHELL, verdict.reason)

    def test_dangerous_schemes_are_refused(self):
        for url in ("https://h.example/fetch?url=gopher://evil.example/",
                    "https://h.example/fetch?url=gopher://169.254.169.254/",
                    "https://h.example/fetch?url=dict://evil.example/",
                    "https://h.example/fetch?url=file:///etc/passwd"):
            with self.subTest(url=url):
                verdict = _admit("GET", url)
                self.assertFalse(verdict.allowed, url)
                self.assertEqual(A.DANGEROUS_SCHEME, verdict.reason)

    def test_intranet_and_metadata_http_ssrf_existence_is_allowed(self):
        """SSRF 存在性要让目标去读回环 / 内网一口 / 云元数据。"""
        cases = (
            "https://h.example/fetch?url=http://127.0.0.1/",
            "https://h.example/fetch?url=http://10.1.2.3/admin",
            "https://h.example/fetch?url=http://192.168.1.1/",
            "https://h.example/fetch?url=http://169.254.169.254/latest/meta-data/",
            "https://h.example/fetch?url=http://metadata.google.internal/",
            "https://h.example/fetch?url=http://100.100.100.200/latest/meta-data/",
            "https://h.example/fetch?url=http://2130706433/",
        )
        for url in cases:
            with self.subTest(url=url):
                self.assertTrue(_admit("GET", url).allowed, url)

    def test_the_request_host_being_loopback_is_not_a_payload(self):
        """本地靶场 ``http://127.0.0.1:8080/api/orders`` 是目标本身，不是 SSRF 取值。"""
        self.assertTrue(_admit("GET", "http://127.0.0.1:8080/api/orders").allowed)

    def test_external_hostname_callback_stays_allowed_on_get(self):
        """既有契约:``GET ?url=https://internal.example/`` 必须继续放行。"""
        self.assertTrue(_admit(
            "GET", "https://h.example/api/fetch?url=https://internal.example/").allowed)

    def test_a_version_looking_private_ip_is_not_flagged_on_a_plain_id(self):
        self.assertTrue(_admit("GET", "https://h.example/api/item?version=10.0.0.1").allowed)

    def test_a_proven_post_with_short_sleep_in_the_body_is_allowed(self):
        verdict = _admit(
            "POST", "https://h.example/api/x?action=query",
            body='{"q": "1\' AND SLEEP(5)--"}', content_type="application/json")
        self.assertTrue(verdict.allowed, verdict.reason)

    def test_a_proven_post_with_insert_in_the_body_is_allowed(self):
        verdict = _admit(
            "POST", "https://h.example/api/x?action=query",
            body='{"q": "1\'; INSERT INTO canary VALUES(1)--"}',
            content_type="application/json")
        self.assertTrue(verdict.allowed, verdict.reason)

    def test_a_proven_post_with_delete_in_the_body_is_refused(self):
        verdict = _admit(
            "POST", "https://h.example/api/x?action=query",
            body='{"q": "1\'; DELETE FROM audit--"}',
            content_type="application/json")
        self.assertFalse(verdict.allowed)
        self.assertEqual(A.DESTRUCTIVE_SQL, verdict.reason)

    def test_payload_gate_does_not_need_the_classifier(self):
        with patch.object(A, "_guardrails", return_value=(None, None, "ImportError: boom")):
            self.assertTrue(_admit("GET", "https://h.example/api/orders").allowed)
            self.assertTrue(_admit("GET", "https://h.example/item?id=1'+AND+SLEEP(5)--").allowed)
            verdict = _admit("GET", "https://h.example/item?id=1'+AND+BENCHMARK(5000000,SHA1(1))--")
            self.assertFalse(verdict.allowed)
            self.assertEqual(A.RESOURCE_EXHAUSTION, verdict.reason)


class BytesrcOverlayTests(unittest.TestCase):
    """ByteSRC V6 / 测试红线：本场禁止系统命令、内网 SSRF、读主机文件。"""

    def test_program_detection(self):
        self.assertTrue(A.is_bytesrc_program("bytesrc", ""))
        self.assertTrue(A.is_bytesrc_program("", "ByteSRC 安全报告处置规则 V6.0"))
        self.assertTrue(A.is_bytesrc_program("字节跳动-src", "书面授权"))
        self.assertFalse(A.is_bytesrc_program("jsrc-double11", "JSRC 双十一"))
        self.assertFalse(A.is_bytesrc_program("test-program", "written authorization for test"))

    def test_ordinary_reads_and_boolean_sqli_still_go_out(self):
        for url in (
            "https://h.example/api/orders?page=2",
            "https://h.example/item?id=1",
            "https://h.example/item?id=1'+AND+1=1--",
            "https://h.example/item?id=1'+AND+SLEEP(5)--",
        ):
            with self.subTest(url=url):
                verdict = A.admit(method="GET", url=url, program="bytesrc")
                self.assertTrue(verdict.allowed, url)

    def test_system_command_probes_are_refused(self):
        cases = (
            "https://h.example/run?q=whoami",
            "https://h.example/run?q=1;id",
            "https://h.example/run?q=1;time",
            "https://h.example/run?q=echo%20LODE1",
            "https://h.example/run?q=system('id')",
            "https://h.example/file?path=../../etc/passwd",
        )
        for url in cases:
            with self.subTest(url=url):
                verdict = A.admit(method="GET", url=url, program="bytesrc")
                self.assertFalse(verdict.allowed, url)
                self.assertEqual(A.SYSTEM_COMMAND, verdict.reason)

    def test_insert_canary_is_still_refused_on_bytesrc(self):
        """ByteSRC 红线 5 禁止增删改，INSERT 也不能发。"""
        verdict = A.admit(
            method="GET",
            url="https://h.example/item?q=1'+INSERT+INTO+canary+VALUES(1)--",
            program="bytesrc",
        )
        self.assertFalse(verdict.allowed)
        self.assertEqual(A.DESTRUCTIVE_SQL, verdict.reason)

    def test_intranet_and_metadata_ssrf_are_refused(self):
        cases = (
            "https://h.example/fetch?url=http://127.0.0.1/",
            "https://h.example/fetch?url=http://10.1.2.3/admin",
            "https://h.example/fetch?url=http://169.254.169.254/latest/meta-data/",
            "https://h.example/fetch?url=http://metadata.google.internal/",
        )
        for url in cases:
            with self.subTest(url=url):
                verdict = A.admit(method="GET", url=url, program="bytesrc")
                self.assertFalse(verdict.allowed, url)
                self.assertEqual(A.INTRANET_OR_METADATA, verdict.reason)

    def test_external_callback_ssrf_stays_allowed(self):
        verdict = A.admit(
            method="GET",
            url="https://h.example/api/fetch?url=https://collab.example/flag",
            program="bytesrc",
        )
        self.assertTrue(verdict.allowed, verdict.reason)

    def test_other_programs_keep_existence_probes(self):
        self.assertTrue(A.admit(
            method="GET", url="https://h.example/run?q=1;id", program="jsrc").allowed)
        self.assertTrue(A.admit(
            method="GET",
            url="https://h.example/fetch?url=http://169.254.169.254/",
            program="jsrc",
        ).allowed)


if __name__ == "__main__":
    unittest.main()
