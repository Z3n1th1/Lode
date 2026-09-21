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

    def __init__(self, target: str, payload: dict | None = None, turn_id: str = "") -> None:
        self.target = target
        self.payload = payload or {}
        self.turn_id = turn_id


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


class ReadOnlyByConstructionTests(unittest.TestCase):
    """没有授权文档的两条路按构造只读,而且要是**显式**的。

    能力只能来自操作员签的那份文档。这两条路上没有文档,所以既没有可推导的东西,
    也不该从别处推 —— 从开关推、从模型推、从"缺省恰好比较宽"推,都是在发明授权。
    把字段显式写出来,未来某次改动就没法不小心把这条路放开。
    """

    def test_a_typed_url_is_read_only(self) -> None:
        scope = _scope("https://api.nba.com/")
        self.assertEqual(("GET", "HEAD"), scope.allowed_methods)
        self.assertFalse(scope.allow_request_body)

    def test_a_confirmed_card_is_read_only(self) -> None:
        card = {"scope": {"allowed_hosts": ["api.nba.com"], "forbidden_hosts": []},
                "target_id": "t-1"}
        scope = jobs._scope_from_confirmed_card(card, target_id="t-1", run_id="r1",
                                                engagement="turn-x", delay=0.5)
        self.assertEqual(("GET", "HEAD"), scope.allowed_methods)
        self.assertFalse(scope.allow_request_body)

    def test_a_card_cannot_declare_a_capability_even_if_the_data_says_so(self) -> None:
        """卡里就算塞了 allowed_methods 也没用 —— 卡的 schema 里根本没有这一栏。"""
        card = {"scope": {"allowed_hosts": ["api.nba.com"], "forbidden_hosts": [],
                          "allowed_methods": ["GET", "POST"], "allow_request_body": True},
                "target_id": "t-1"}
        scope = jobs._scope_from_confirmed_card(card, target_id="t-1", run_id="r1",
                                                engagement="turn-x", delay=0.5)
        self.assertEqual(("GET", "HEAD"), scope.allowed_methods)
        self.assertFalse(scope.allow_request_body)

    def test_only_the_document_path_can_carry_a_capability(self) -> None:
        """对照:授权文档那条路必须继承方法维度,否则这次改动就只做了一半。"""
        scope = jobs._scope_from_engagement_document(
            {"program": "p", "authorization": "a", "allowed_hosts": ["a.example", "b.example"],
             "allowed_methods": ["GET", "POST"], "allow_request_body": True},
            host="a.example", authorization_id="A-1", run_id="r1", engagement="e",
        )
        self.assertEqual(("GET", "HEAD", "POST"), scope.allowed_methods)
        self.assertTrue(scope.allow_request_body)


class RunIdentityTests(unittest.TestCase):
    """一次对话 = 一次 engagement;一次对话里的所有 job 合起来只有一份预算。

    桶本身在 ``core/rate_limit``(它有一整套测试)。这里钉的是 Console 这一侧交出
    去的身份:是不是那次对话,以及两条入口(手打的 URL / 确认过的卡片)是不是同一
    个节奏 —— 它们以前是两个答案(0.5 与 dataclass 默认 0.4)。
    """

    def test_a_typed_job_draws_on_its_conversation(self) -> None:
        job = _Job("https://a.example.com/", {"run_id": "SA-1"}, turn_id="T-abc")
        scope = jobs._typed_target_scope(job, run_id="SA-1", target_url=job.target)
        self.assertEqual("turn-T-abc", scope.engagement)
        self.assertEqual("console-SA-1", scope.program)   # 显示名照旧,一个 job 一个

    def test_a_declared_program_beats_the_conversation(self) -> None:
        """scope 里点了名的程序就是这次 engagement 自己的身份,不用对话号顶替。"""
        job = _Job("https://a.example.com/", {"program": "nba"}, turn_id="T-abc")
        scope = jobs._typed_target_scope(job, run_id="SA-1", target_url=job.target)
        self.assertEqual("nba", scope.engagement)

    def test_without_a_turn_it_still_gets_a_unique_identity(self) -> None:
        """没有 turn(老调用方/手工构造)不能退化成空键 —— 那样所有 job 会并成一个桶。"""
        scope = jobs._typed_target_scope(_Job("https://a.example.com/"), run_id="SA-9",
                                         target_url="https://a.example.com/")
        self.assertEqual("console-SA-9", scope.engagement)

    def test_the_card_path_and_the_typed_path_pace_the_same(self) -> None:
        job = _Job("https://a.example.com/")
        card_scope = jobs._scope_from_confirmed_card(
            {"scope": {"allowed_hosts": ["a.example.com"]}}, target_id="t1", run_id="r1",
            engagement=jobs._engagement(job, run_id="r1"), delay=jobs._scope_delay(job))
        self.assertEqual(_scope("https://a.example.com/").delay_seconds, card_scope.delay_seconds)

    def test_both_constructors_take_the_pace_from_the_same_place(self) -> None:
        job = _Job("https://a.example.com/", {"delay_seconds": 1.0})
        card_scope = jobs._scope_from_confirmed_card(
            {"scope": {"allowed_hosts": ["a.example.com"]}}, target_id="t1", run_id="r1",
            engagement="turn-T", delay=jobs._scope_delay(job))
        self.assertEqual(1.0, card_scope.delay_seconds)


class PersistedRunScopeTests(unittest.TestCase):
    """``SrcRunScope/v1`` 是事后唯一能读的授权记录,所以它必须说真话。

    它以前只记域/主机列表,不记能力 —— "这次跑到底允不允许 POST"从记录里答不出来,
    答案在 agents/src_agent.py 的一个常量里。engagement 同理:一个没人叫得出名字的
    预算,没人审得动。
    """

    def test_the_record_carries_the_capability_and_the_budget_identity(self) -> None:
        from agents.surface_discovery import SurfaceScope

        scope = SurfaceScope(
            "nba", "written authorization", engagement="turn-T-1",
            allowed_hosts=("api.nba.com",), allowed_methods=("POST",), allow_request_body=True,
        )
        doc = jobs._scope_document(scope, run_id="SL-1", reasoner="deepseek", explorer="claude")

        self.assertEqual("SrcRunScope/v1", doc["schema"])
        self.assertEqual("turn-T-1", doc["engagement"])
        self.assertEqual(["api.nba.com"], doc["allowed_hosts"])
        self.assertEqual(["GET", "HEAD", "POST"], doc["allowed_methods"])
        self.assertIs(True, doc["allow_request_body"])

    def test_a_read_only_scope_records_read_only(self) -> None:
        scope = _scope("https://a.example.com/")
        doc = jobs._scope_document(scope, run_id="SL-2")
        self.assertEqual(["GET", "HEAD"], doc["allowed_methods"])
        self.assertIs(False, doc["allow_request_body"])
        self.assertEqual("console-r1", doc["engagement"])   # 没有 turn 时退回 run


class RateDeclarationTests(unittest.TestCase):
    """Console 这一侧也能按 req/s 说速度,而不是让操作员手算间隔。

    程序文档写的是 "3 req/s";让人自己算 0.333 再填进 payload,是把折算这件事交给
    最没有理由精确的一方。和 scope 文件同一条规矩:req/s 在时按它走。
    """

    def test_a_rate_in_the_payload_is_converted_not_ignored(self) -> None:
        self.assertAlmostEqual(1 / 3, jobs._scope_delay(_Job("https://a.example.com/",
                                                             {"requests_per_second": 3})), places=6)

    def test_the_rate_wins_over_a_hand_rounded_delay(self) -> None:
        job = _Job("https://a.example.com/", {"requests_per_second": 4, "delay_seconds": 2.0})
        self.assertEqual(0.25, jobs._scope_delay(job))

    def test_the_rate_can_come_from_the_environment(self) -> None:
        with patch.dict(os.environ, {"LODE_REQUESTS_PER_SECOND": "2"}):
            self.assertEqual(0.5, jobs._scope_delay(_Job("https://a.example.com/")))

    def test_the_payloads_rate_beats_the_environments_delay(self) -> None:
        """两处都说了话时,单位更明确的那个赢 —— 不是"更晚读到的那个"。"""
        with patch.dict(os.environ, {"LODE_SURFACE_DELAY_SECONDS": "2.0"}):
            self.assertEqual(0.25, jobs._scope_delay(
                _Job("https://a.example.com/", {"requests_per_second": 4})))

    def test_an_unusable_rate_falls_back_to_the_delay_it_used_to_use(self) -> None:
        for rate in ("fast", 0):
            with self.subTest(rate=rate), patch.dict(os.environ, {"LODE_REQUESTS_PER_SECOND": ""}):
                self.assertEqual(1.0, jobs._scope_delay(
                    _Job("https://a.example.com/", {"requests_per_second": rate,
                                                    "delay_seconds": 1.0})))

    def test_the_scope_built_from_it_carries_the_rate(self) -> None:
        scope = _scope("https://a.example.com/", {"requests_per_second": 3})
        self.assertAlmostEqual(3.0, scope.requests_per_second, places=6)

    def test_the_record_keeps_both_spellings(self) -> None:
        """事后审的人要能直接读到程序写的那个数,而不是拿 1/delay 反算。"""
        doc = jobs._scope_document(_scope("https://a.example.com/",
                                          {"requests_per_second": 3}), run_id="SL-1")
        self.assertAlmostEqual(3.0, doc["requests_per_second"], places=6)


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
