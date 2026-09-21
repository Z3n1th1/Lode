"""Tests for agents.src_agent — LLM-driven SRC agent loop."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT))
sys.path.insert(0, str(_PROJECT_ROOT / "core"))

from agents.src_agent import (
    SUMMARY_SCHEMA,
    MAX_ROUTE_PROPOSALS_PER_CYCLE,
    ExploreResult,
    SrcAgentLoop,
    AgentConfig,
    EXPLORER_SYSTEM,
    REASONER_SYSTEM,
    HTTP_ACTION_LOG,
    _blackboard_to_context,
    _fetch_for_analysis,
    _parse_json_response,
    _sanitize_headers,
    _shape_signals_section,
    run_src_agent,
)
from agents.surface_discovery import SurfaceScope
from core.src_blackboard import SrcBlackboard


def _make_scope(**kwargs) -> SurfaceScope:
    defaults = dict(
        program="test-program",
        authorization="written authorization for test",
        allowed_domains=("example.com",),
        delay_seconds=0.0,
        timeout_seconds=5.0,
    )
    defaults.update(kwargs)
    return SurfaceScope(**defaults)


def _seed_blackboard(bb: SrcBlackboard, n: int = 3) -> None:
    candidates = []
    for i in range(n):
        candidates.append({
            "candidate_id": f"SC-test{i:03d}",
            "url": f"https://example.com/api/endpoint{i}",
            "priority": 80 - i * 10,
            "sources": ["openapi"],
            "next_phase": "A-passive-triage",
        })
    bb.sync_candidates(candidates, run_id="test-seed")


class TestJsonParsing(unittest.TestCase):
    def test_direct_json(self):
        self.assertEqual(_parse_json_response('{"a": 1}'), {"a": 1})

    def test_markdown_fence(self):
        self.assertEqual(_parse_json_response('```json\n{"b": 2}\n```'), {"b": 2})

    def test_fence_no_lang(self):
        self.assertEqual(_parse_json_response('```\n{"c": 3}\n```'), {"c": 3})

    def test_leading_text(self):
        self.assertEqual(_parse_json_response('Here is my analysis:\n{"d": 4}\nDone.'), {"d": 4})

    def test_empty(self):
        self.assertIsNone(_parse_json_response(""))
        self.assertIsNone(_parse_json_response("   "))

    def test_none(self):
        self.assertIsNone(_parse_json_response(None))  # type: ignore[arg-type]

    def test_not_json(self):
        self.assertIsNone(_parse_json_response("This is just text without JSON"))

    def test_array_rejected(self):
        self.assertIsNone(_parse_json_response('[1, 2, 3]'))

    def test_nested_json(self):
        result = _parse_json_response('{"a": {"b": [1, 2]}, "c": true}')
        self.assertEqual(result, {"a": {"b": [1, 2]}, "c": True})


class TestBlackboardContext(unittest.TestCase):
    def test_empty_snapshot(self):
        ctx = _blackboard_to_context({"facts": [], "intents": [], "dead_ends": [], "hints": []})
        self.assertIn("Facts: (none)", ctx)
        self.assertIn("Queued Intents: (none)", ctx)

    def test_with_data(self):
        snapshot = {
            "facts": [{"fact_id": "F-001", "kind": "src_candidate", "url": "https://example.com/api", "priority": 80, "confidence": "observed", "sources": ["openapi"]}],
            "intents": [{"intent_id": "I-001", "target": "https://example.com/api", "priority": 80, "phase": "A-passive-triage", "status": "queued", "candidate_id": "SC-001"}],
            "dead_ends": [{"dead_end_id": "D-001", "intent_id": "I-old", "reason": "404 not found"}],
            "hints": [{"hint_id": "H-001", "intent_id": "I-001", "hint": "check auth", "source": "operator"}],
        }
        ctx = _blackboard_to_context(snapshot)
        self.assertIn("F-001", ctx)
        self.assertIn("I-001", ctx)
        self.assertIn("D-001", ctx)
        self.assertIn("H-001", ctx)
        self.assertIn("Queued Intents (1 available)", ctx)

    def test_queued_intents_show_their_shape_signals(self):
        """形状信号要出现在 reasoner 选的这一行上,不然它只能看见一个裸 URL。"""
        snapshot = {
            "facts": [], "dead_ends": [], "hints": [],
            "intents": [{"intent_id": "I-001", "target": "https://example.com/admin/export?customer_id=[redacted]",
                         "priority": 80, "phase": "A-passive-triage", "status": "queued",
                         "candidate_id": "SC-001", "hypotheses": ["idor", "authz_boundary"]}],
        }
        ctx = _blackboard_to_context(snapshot)
        self.assertIn("shapes=idor,authz_boundary", ctx)

    def test_an_intent_with_no_signal_gets_no_shapes_note(self):
        """空就是空 —— 补一句 "shapes=-" 只会让每一行都变长。"""
        snapshot = {
            "facts": [], "dead_ends": [], "hints": [],
            "intents": [{"intent_id": "I-001", "target": "https://example.com/health",
                         "priority": 10, "status": "queued", "candidate_id": "SC-001"}],
        }
        ctx = _blackboard_to_context(snapshot)
        self.assertNotIn("shapes=", ctx)

    def test_truncation_keeps_the_highest_scoring_intents(self):
        """黑板把 intents 按优先级降序存,所以取尾部就是取最低分的那一段。

        60 个 intent、上限 50:老写法永远丢掉分数最高的 10 个 —— 模型看不到最该
        看的那些,而且候选越多越严重。对照组是 facts:它是插入序,取尾部才是对的。
        """
        intents = [
            {"intent_id": f"I-{index:03d}", "target": f"https://example.com/p{index}",
             "priority": 100 - index, "phase": "A-passive-triage", "status": "queued",
             "candidate_id": f"SC-{index:03d}"}
            for index in range(60)
        ]
        ctx = _blackboard_to_context({"facts": [], "intents": intents, "dead_ends": [], "hints": []})
        self.assertIn("I-000", ctx)                 # priority 100 —— 最该被看见的
        self.assertNotIn("I-059", ctx)              # priority 41 —— 截掉
        self.assertIn("Queued Intents (60 available)", ctx)

    def test_non_queued_intents_are_capped_after_the_split(self):
        """先分再截:已完成的 intent 不能把 queued 的名额挤掉。"""
        intents = [{"intent_id": f"I-q{index}", "target": "https://example.com/", "priority": 90,
                    "status": "queued", "candidate_id": f"SC-q{index}"} for index in range(3)]
        intents += [{"intent_id": f"I-d{index}", "target": "https://example.com/", "priority": 95,
                     "status": "dead_end", "candidate_id": f"SC-d{index}"} for index in range(40)]
        ctx = _blackboard_to_context({"facts": [], "intents": intents, "dead_ends": [], "hints": []},
                                     max_intents=2, max_other_intents=1)
        for index in range(2):
            self.assertIn(f"I-q{index}", ctx)
        self.assertIn("I-d0", ctx)                  # other 只留最前面那条
        self.assertNotIn("I-d1", ctx)


class TestSanitizeHeaders(unittest.TestCase):
    def test_redacts_sensitive(self):
        headers = {"content-type": "text/html", "set-cookie": "session=abc123", "x-debug": "true"}
        result = _sanitize_headers(headers)
        self.assertIn("[redacted]", result)
        self.assertNotIn("abc123", result)
        self.assertIn("x-debug: true", result)


class TestFetchForAnalysis(unittest.TestCase):
    def test_scope_rejected(self):
        scope = _make_scope()
        result = _fetch_for_analysis("https://evil.com/api", scope)
        self.assertIn("scope_rejected", result["error"])

    def test_write_blocked(self):
        """原因说准确:这是"URL 读起来像改状态",不是笼统的 write_blocked。

        以前不管什么原因都叫 write_blocked:,于是 URL 里带 "update" 的一个 POST 被
        说成"写操作被拦",而真正的原因是方法没被声明 —— 操作员照着一个错的理由去
        改 scope 只会更困惑。
        """
        scope = _make_scope()
        result = _fetch_for_analysis("https://example.com/api/deleteUser", scope)
        self.assertEqual("state_changing_endpoint", result["error"])

    def test_successful_fetch(self):
        scope = _make_scope()
        def mock_fetch(url, **kw):
            return 200, '{"ok": true}', {"content-type": "application/json"}
        result = _fetch_for_analysis("https://example.com/api/users", scope, fetcher=mock_fetch)
        self.assertEqual(result["status"], 200)
        self.assertEqual(result["error"], "")
        self.assertIn("ok", result["body"])


class TestSrcAgentLoop(unittest.TestCase):

    def _make_mocks(self, *, reasoner_response=None, explorer_response=None,
                    should_stop=False, fetch_status=200, fetch_body='{"data": []}'):
        calls: List[Tuple[str, str]] = []

        def mock_complete(system, user, **kwargs):
            calls.append(("reasoner" if "Reasoner" in system else "explorer", user[:50]))
            if "Reasoner" in system:
                if reasoner_response is not None:
                    return reasoner_response
                return json.dumps({
                    "reasoning": "test",
                    "selected_intents": [{
                        "intent_id": "I-placeholder",  # will be replaced
                        "hypothesis": "test hypothesis",
                        "check_description": "test check",
                        "expected_evidence": "test evidence",
                    }],
                    "should_stop": should_stop,
                })
            if "Explorer" in system:
                if explorer_response is not None:
                    return explorer_response
                return json.dumps({
                    "analysis": "test analysis",
                    "findings": [{
                        "type": "information_disclosure",
                        "confidence": "medium",
                        "evidence": "X-Debug header found",
                        "description": "Debug mode enabled",
                    }],
                    "conclusion": "confirmed",
                })
            return None

        def mock_fetcher(url, **kw):
            return fetch_status, fetch_body, {"content-type": "application/json"}

        return calls, mock_complete, mock_fetcher

    def test_full_cycle_with_findings(self):
        calls, mock_complete, mock_fetcher = self._make_mocks()
        with tempfile.TemporaryDirectory() as tmp:
            bb_path = Path(tmp) / "bb.json"
            scope = _make_scope()
            bb = SrcBlackboard(bb_path)
            _seed_blackboard(bb, 2)

            # Patch reasoner to use actual intent IDs
            snap = bb.snapshot()
            first_intent_id = snap["intents"][0]["intent_id"]

            def patched_complete(system, user, **kwargs):
                if "Reasoner" in system:
                    return json.dumps({
                        "reasoning": "test",
                        "selected_intents": [{
                            "intent_id": first_intent_id,
                            "hypothesis": "IDOR test",
                            "check_description": "check IDs",
                            "expected_evidence": "other user data",
                        }],
                        "should_stop": False,
                    })
                return mock_complete(system, user, **kwargs)

            summary = run_src_agent(
                bb_path, scope,
                max_cycles=2,
                fetcher=mock_fetcher,
                llm_complete_fn=patched_complete,
                worker_id="test-w",
            )

            self.assertEqual(summary["schema"], SUMMARY_SCHEMA)
            self.assertGreaterEqual(summary["total_explored"], 1)
            snap = bb.snapshot()
            self.assertTrue(any(h.get("source") == "src_agent_explorer" for h in snap.get("hints", [])))

    def test_high_confidence_findings_reach_the_summary(self):
        """``needs_human`` 那种发现必须进 total_findings。

        高置信 finding 走的是 needs_human(标 blocked、等人工复核),既不是
        ``fact_added`` 也不是 ``dead_end``。旧写法只累加 ``fact_added``,于是**置信度
        最高的那几条发现反而不计数** —— 黑板上有 hint,摘要报 0,操作员以为什么都没挖到。
        2026-09-21 在 login-dev.nba.com 上实测踩到:3 条 high 置信 hint / total_findings 0。
        """
        with tempfile.TemporaryDirectory() as tmp:
            bb_path = Path(tmp) / "bb.json"
            bb = SrcBlackboard(bb_path)
            _seed_blackboard(bb, 1)
            intent_id = bb.snapshot()["intents"][0]["intent_id"]

            def complete(system, user, **kwargs):
                if "Reasoner" in system:
                    return json.dumps({
                        "reasoning": "t", "should_stop": False,
                        "selected_intents": [{"intent_id": intent_id,
                                              "hypothesis": "版本泄露",
                                              "check_description": "读 version"}],
                    })
                return json.dumps({
                    "analysis": "未认证可读", "conclusion": "confirmed",
                    "findings": [{"type": "info_disclosure", "confidence": "high",
                                  "evidence": "GET /openidm/info/version -> 200 {\"productVersion\":\"9.0.0\"}",
                                  "description": "未认证泄露精确版本"}],
                })

            summary = run_src_agent(bb_path, _make_scope(), max_cycles=2,
                                    fetcher=lambda url, **kw: (200, "{}", {}),
                                    llm_complete_fn=complete, worker_id="test-w")
            hints = bb.snapshot().get("hints", [])

        self.assertEqual(0, summary["total_dead_ends"])
        self.assertEqual(1, summary["total_findings"],
                         "high 置信发现被 needs_human 分支吞掉了,摘要会报 0")
        self.assertTrue(any(h.get("source") == "src_agent_explorer" for h in hints))

    def test_no_queued_intents_stops(self):
        calls, mock_complete, mock_fetcher = self._make_mocks()
        with tempfile.TemporaryDirectory() as tmp:
            bb_path = Path(tmp) / "bb.json"
            scope = _make_scope()
            bb = SrcBlackboard(bb_path)
            bb.ensure()  # empty blackboard

            summary = run_src_agent(
                bb_path, scope,
                max_cycles=5,
                fetcher=mock_fetcher,
                llm_complete_fn=mock_complete,
                worker_id="test-w",
            )
            self.assertEqual(summary["stop_reason"], "no_queued_intents")
            self.assertEqual(summary["total_explored"], 0)

    def test_reasoner_failure_stops(self):
        with tempfile.TemporaryDirectory() as tmp:
            bb_path = Path(tmp) / "bb.json"
            scope = _make_scope()
            bb = SrcBlackboard(bb_path)
            _seed_blackboard(bb, 2)

            summary = run_src_agent(
                bb_path, scope,
                max_cycles=5,
                llm_complete_fn=lambda s, u, **kw: None,  # always fails
                worker_id="test-w",
            )
            self.assertEqual(summary["stop_reason"], "reasoner_failed")

    def test_reasoner_should_stop(self):
        calls, mock_complete, mock_fetcher = self._make_mocks(should_stop=True)
        with tempfile.TemporaryDirectory() as tmp:
            bb_path = Path(tmp) / "bb.json"
            scope = _make_scope()
            bb = SrcBlackboard(bb_path)
            _seed_blackboard(bb, 2)

            summary = run_src_agent(
                bb_path, scope,
                max_cycles=5,
                fetcher=mock_fetcher,
                llm_complete_fn=mock_complete,
                worker_id="test-w",
            )
            self.assertIn("stop", summary["stop_reason"].lower())

    def test_scope_required(self):
        scope = SurfaceScope("test", "", allowed_domains=("example.com",))
        with self.assertRaises(ValueError):
            AgentConfig(blackboard_path=Path("/tmp/x"), scope=scope)
            SrcAgentLoop(AgentConfig(blackboard_path=Path("/tmp/x"), scope=scope))

    def test_explorer_dead_end_on_fetch_error(self):
        """Transient fetch error → requeued with retry, terminal only after the cap."""
        with tempfile.TemporaryDirectory() as tmp:
            bb_path = Path(tmp) / "bb.json"
            scope = _make_scope()
            bb = SrcBlackboard(bb_path)
            _seed_blackboard(bb, 1)
            snap = bb.snapshot()
            first_id = snap["intents"][0]["intent_id"]

            def reasoner_returns_intent(system, user, **kw):
                if "Reasoner" in system:
                    return json.dumps({
                        "reasoning": "t", "should_stop": False,
                        "selected_intents": [{"intent_id": first_id, "hypothesis": "h", "check_description": "c"}],
                    })
                return json.dumps({"analysis": "x", "findings": [], "conclusion": "dead_end", "dead_end_reason": "nothing"})

            def failing_fetcher(url, **kw):
                return 0, "", {}

            summary = run_src_agent(
                bb_path, scope,
                max_cycles=4,
                fetcher=failing_fetcher,
                llm_complete_fn=reasoner_returns_intent,
                worker_id="test-w",
            )
            intent = next(i for i in bb.snapshot()["intents"] if i["intent_id"] == first_id)
            # Retried (not dead-ended on the first blip) and only terminal after the cap.
            self.assertGreaterEqual(intent["attempts"], 2)
            self.assertEqual(intent["status"], "dead_end")
            self.assertGreaterEqual(len(summary["errors"]), 1)

    def test_the_explorer_prompt_carries_the_shape_signals(self):
        """URL 形状看出来的检查方向必须进提示词。

        否则 Explorer 面对的永远是同一句 "look for security-relevant patterns",
        每个 intent 都从零开始猜 —— 而形状那点信息是免费的、确定的。
        """
        seen: List[str] = []

        with tempfile.TemporaryDirectory() as tmp:
            bb_path = Path(tmp) / "bb.json"
            bb = SrcBlackboard(bb_path)
            bb.sync_candidates(
                [{"candidate_id": "SC-1", "priority": 80,
                  "url": "https://example.com/admin/export?customer_id=[redacted]"}],
                run_id="SA-1",
            )
            intent_id = bb.snapshot()["intents"][0]["intent_id"]

            def complete(system, user, **kw):
                if "Reasoner" in system:
                    return json.dumps({"reasoning": "t", "should_stop": False,
                                       "selected_intents": [{"intent_id": intent_id,
                                                             "hypothesis": "h", "check_description": "c"}]})
                seen.append(user)
                return json.dumps({"analysis": "x", "findings": [], "conclusion": "dead_end",
                                   "dead_end_reason": "nothing"})

            run_src_agent(bb_path, _make_scope(), max_cycles=2, fetcher=lambda url, **kw: (200, "{}", {}),
                          llm_complete_fn=complete, worker_id="test-w")

        self.assertTrue(seen, "Explorer 一次都没跑到,这条断言无意义")
        prompt = seen[0]
        self.assertIn("Shape signals", prompt)
        self.assertIn("idor", prompt)
        self.assertIn("authz_boundary", prompt)
        # 这条路径没有头部/凭据通道,提示词不能暗示有 —— 否则模型会写一个跑不了的计划。
        self.assertIn("不做凭据重放", prompt)

    def test_explorer_unparseable_response(self):
        """Explorer garbage is transient → retried, dead_end only after the cap."""
        with tempfile.TemporaryDirectory() as tmp:
            bb_path = Path(tmp) / "bb.json"
            scope = _make_scope()
            bb = SrcBlackboard(bb_path)
            _seed_blackboard(bb, 1)
            snap = bb.snapshot()
            first_id = snap["intents"][0]["intent_id"]

            call_count = [0]
            def mixed_complete(system, user, **kw):
                call_count[0] += 1
                if "Reasoner" in system:
                    return json.dumps({
                        "reasoning": "t", "should_stop": False,
                        "selected_intents": [{"intent_id": first_id, "hypothesis": "h", "check_description": "c"}],
                    })
                return "This is not JSON at all, just random text."

            def ok_fetcher(url, **kw):
                return 200, "hello", {"content-type": "text/html"}

            summary = run_src_agent(
                bb_path, scope,
                max_cycles=4,
                fetcher=ok_fetcher,
                llm_complete_fn=mixed_complete,
                worker_id="test-w",
            )
            intent = next(i for i in bb.snapshot()["intents"] if i["intent_id"] == first_id)
            self.assertGreaterEqual(intent["attempts"], 2)
            self.assertEqual(intent["status"], "dead_end")
            self.assertGreaterEqual(len(summary["errors"]), 1)

    def test_stop_is_blocked_while_todos_are_open(self):
        """reasoner says stop, but open workmem todos gate the finish checkpoint."""
        with tempfile.TemporaryDirectory() as tmp:
            bb_path = Path(tmp) / "bb.json"
            scope = _make_scope()
            bb = SrcBlackboard(bb_path)
            _seed_blackboard(bb, 1)
            bb.workmem_apply_todos([
                {"op": "add", "text": "verify IDOR on /user/{id}"},
                {"op": "add", "text": "re-check the 500 endpoint"},
            ])

            def always_stop(system, user, **kw):
                return json.dumps({
                    "reasoning": "looks done", "should_stop": True,
                    "stop_reason": "all_done", "selected_intents": [],
                })

            summary = run_src_agent(
                bb_path, scope,
                max_cycles=5,
                fetcher=lambda url, **kw: (200, "ok", {}),
                llm_complete_fn=always_stop,
                worker_id="test-w",
            )
            self.assertTrue(
                any(str(e).startswith("stop_blocked") for e in summary["errors"]),
                summary["errors"],
            )
            # blocked the configured number of times before finally allowing the stop
            self.assertEqual("all_done", summary["stop_reason"])

    def test_blackboard_not_found(self):
        scope = _make_scope()
        # Hermetic: a path that cannot exist, inside a temp dir (never touches the
        # filesystem root, so the test can't pollute the drive it runs from).
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "does-not-exist" / "bb.json"
            summary = run_src_agent(
                missing, scope,
                max_cycles=1,
                llm_complete_fn=lambda s, u, **kw: None,
                worker_id="test-w",
            )
        self.assertEqual(summary["stop_reason"], "blackboard_not_found")


class TestKnowledgeActivation(unittest.TestCase):
    """激活 + 专精:信号把打法唤醒,唤醒的那本进后续每一轮的 system prompt。

    以前猎场走的是两个硬编码 prompt,一点技能包都拿不到 —— 蒸出来的打法只到得了
    对话轮,到不了真正在挖的那条路。
    """

    def _loop(self, tmp, *, seed=()):
        bb_path = Path(tmp) / "bb.json"
        SrcBlackboard(bb_path)
        return SrcAgentLoop(AgentConfig(blackboard_path=bb_path, scope=_make_scope(),
                                       knowledge_seed=seed))

    def test_seed_activates_before_the_first_cycle(self):
        with tempfile.TemporaryDirectory() as tmp:
            loop = self._loop(tmp, seed=("url-trust",))
        self.assertEqual(["url-trust"], list(loop._activated))
        self.assertIn("白名单", loop._system("BASE"))

    def test_a_signal_activates_the_matching_card(self):
        with tempfile.TemporaryDirectory() as tmp:
            loop = self._loop(tmp)
            added = loop.activate_from_signals("导出组件 exported deep link", source="test")
            self.assertEqual(["mobile"], added)
        self.assertIn("Android", loop._system("BASE"))
        self.assertEqual("test", loop._activation_log[0]["source"])
        self.assertEqual("module:pentest", loop._activation_log[0]["library"])

    def test_the_model_can_name_a_card_outright(self):
        with tempfile.TemporaryDirectory() as tmp:
            loop = self._loop(tmp)
            self.assertEqual(["url-trust"], loop.activate(["url-trust"], source="reasoner"))
            # 幂等:同一个名字再来一次不该重复占预算
            self.assertEqual([], loop.activate(["url-trust"], source="reasoner"))
            self.assertEqual(1, len(loop._activated))

    def test_a_long_knowledge_base_card_is_capped_harder_than_a_module(self):
        """激活的正文每轮都要付一次,所以单卡上限比 read_knowledge 的 12k 紧得多。"""
        from agents.src_agent import KNOWLEDGE_CARD_CHARS

        with tempfile.TemporaryDirectory() as tmp:
            loop = self._loop(tmp)
            self.assertEqual(["idor-test"], loop.activate(["idor-test"], source="t"))
            self.assertLessEqual(len(loop._activated["idor-test"]), KNOWLEDGE_CARD_CHARS + 120)
            # 进了 kb 那一层,而不是当成同名模块
            self.assertEqual("kb", loop._activation_log[0]["library"])

    def test_activation_is_capped_in_count_and_chars(self):
        from agents.src_agent import KNOWLEDGE_MAX_ACTIVE, KNOWLEDGE_TOTAL_CHARS

        with tempfile.TemporaryDirectory() as tmp:
            loop = self._loop(tmp)
            added = loop.activate(
                ["mobile", "url-trust", "idor", "ssrf", "injection", "auth"], source="t")
        self.assertLessEqual(len(added), KNOWLEDGE_MAX_ACTIVE)
        self.assertLessEqual(sum(len(t) for t in loop._activated.values()),
                             KNOWLEDGE_TOTAL_CHARS + 200)

    def test_a_name_that_does_not_exist_activates_nothing(self):
        """不存在的卡名不能进上下文 —— 那等于给模型指一个不存在的门。"""
        with tempfile.TemporaryDirectory() as tmp:
            loop = self._loop(tmp)
            self.assertEqual([], loop.activate(["no-such-card", "../escape", ""], source="t"))
            self.assertEqual({}, loop._activated)

    def test_what_the_reasoner_saw_is_active_from_the_next_cycle(self):
        """专精的关键:这一轮认出来的东西,下一轮才在 prompt 里 —— 顺序别写反。"""
        systems: List[str] = []

        def mock_complete(system, user, **kwargs):
            systems.append(system)
            return json.dumps({
                "reasoning": "这个目标看着是安卓客户端,有导出组件",
                "selected_intents": [],
                "should_stop": True,
            })

        with tempfile.TemporaryDirectory() as tmp:
            loop = self._loop(tmp)
            loop._complete = mock_complete
            _seed_blackboard(loop.blackboard, 1)   # 建锁文件:snapshot 需要它
            loop._reason(loop.blackboard.snapshot())
            self.assertNotIn("已激活的打法", systems[0])   # 第一轮还没激活
            loop._reason(loop.blackboard.snapshot())
            self.assertIn("已激活的打法", systems[1])      # 第二轮带着它上路

        self.assertEqual(["mobile"], list(loop._activated))


class TestSingleDoctrineCopy(unittest.TestCase):
    """doctrine 只留一份(技能包)。角色提示和最后兜底各留一份副本,迟早会漂 —— 而且
    没有任何东西会提醒你它们已经不一致了。这组测试就是那个提醒。
    """

    DOCTRINE = ("授权安全研究员", "真价值优先", "不挖 CORS")

    def test_the_pack_is_where_the_doctrine_lives(self):
        from core import skills

        text = skills.compose_prompt("pentest")
        for phrase in self.DOCTRINE:
            self.assertIn(phrase, text)

    def test_the_role_prompts_do_not_restate_it(self):
        for name, text in (("reasoner", REASONER_SYSTEM), ("explorer", EXPLORER_SYSTEM)):
            for phrase in self.DOCTRINE:
                self.assertNotIn(phrase, text, f"{name} 又抄了一份 doctrine")

    def test_the_last_resort_fallback_is_not_a_persona(self):
        """pack 读不到时它要说明"没拿到规范",不是假装自己就是规范。"""
        from agents.src_chat import SRC_SYSTEM_PROMPT

        for phrase in self.DOCTRINE:
            self.assertNotIn(phrase, SRC_SYSTEM_PROMPT)
        self.assertLess(len(SRC_SYSTEM_PROMPT), 500)

    def test_the_hunt_still_gets_the_doctrine_at_runtime(self):
        """收成一份的前提是它真的被拼进去了 —— 不是被删了。"""
        with tempfile.TemporaryDirectory() as tmp:
            bb_path = Path(tmp) / "bb.json"
            SrcBlackboard(bb_path)
            loop = SrcAgentLoop(AgentConfig(blackboard_path=bb_path, scope=_make_scope()))
            system = loop._system(REASONER_SYSTEM)
        self.assertIn("授权安全研究员", system)      # 来自技能包
        self.assertIn("你是 SRC Reasoner", system)   # 角色契约也还在


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        from agents.src_agent import _self_test
        self.assertEqual(_self_test(), 0)


class TestSrcAgentDagTimelineRecall(unittest.TestCase):
    """reasoner-produced DAG edges, auto timeline compression, and memory reuse."""

    def test_reasoner_dependencies_are_persisted_and_ordered(self):
        with tempfile.TemporaryDirectory() as tmp:
            bb_path = Path(tmp) / "bb.json"
            scope = _make_scope()
            bb = SrcBlackboard(bb_path)
            _seed_blackboard(bb, 2)
            snap = bb.snapshot()
            first_id = snap["intents"][0]["intent_id"]   # priority 80
            second_id = snap["intents"][1]["intent_id"]  # priority 70

            def reasoner_with_dep(system, user, **kw):
                if "Reasoner" in system:
                    return json.dumps({
                        "reasoning": "B needs A's result first",
                        "should_stop": False,
                        "selected_intents": [{
                            "intent_id": second_id,
                            "hypothesis": "IDOR on B",
                            "check_description": "check ids",
                            "depends_on": [first_id],
                        }],
                    })
                return json.dumps({
                    "analysis": "ok",
                    "findings": [{
                        "type": "information_disclosure", "confidence": "medium",
                        "evidence": "X-Debug header", "description": "debug mode",
                    }],
                    "conclusion": "confirmed",
                })

            summary = run_src_agent(
                bb_path, scope,
                max_cycles=4,
                fetcher=lambda url, **kw: (200, '{"ok": true}', {"content-type": "application/json"}),
                llm_complete_fn=reasoner_with_dep,
                worker_id="test-w",
            )

            final = {i["intent_id"]: i for i in bb.snapshot()["intents"]}
            # The edge the reasoner produced is now live on the blackboard.
            self.assertEqual([first_id], final[second_id]["depends_on"])
            # The dependent ran only after its blocker was resolved.
            self.assertEqual("completed", final[first_id]["status"])
            self.assertIn(final[second_id]["status"], ("completed", "blocked", "dead_end"))
            self.assertGreaterEqual(summary["total_explored"], 2)

    def test_blocking_dep_resolution(self):
        snapshot = {"intents": [
            {"intent_id": "A", "status": "queued", "depends_on": []},
            {"intent_id": "B", "status": "queued", "depends_on": ["A"]},
        ]}
        self.assertEqual("A", SrcAgentLoop._blocking_dep(snapshot, "B"))
        self.assertEqual("", SrcAgentLoop._blocking_dep(snapshot, "A"))
        snapshot["intents"][0]["status"] = "completed"
        self.assertEqual("", SrcAgentLoop._blocking_dep(snapshot, "B"))

    def test_timeline_auto_compress_on_long_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            bb_path = Path(tmp) / "bb.json"
            scope = _make_scope()
            bb = SrcBlackboard(bb_path)
            bb.ensure()
            for i in range(6):
                bb.timeline_append("fetch", summary=f"GET {i}")
            agent = SrcAgentLoop(AgentConfig(
                blackboard_path=bb_path, scope=scope,
                timeline_keep=2, enable_timeline_compress=True,
            ))
            agent._maybe_compress_timeline()
            snap = bb.snapshot()
            self.assertGreaterEqual(snap["timeline_head"]["version"], 1)
            self.assertLessEqual(len(snap["timeline"]), 2)
            self.assertIn("fetch", snap["timeline_head"]["text"])

    def test_timeline_compress_can_be_disabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            bb_path = Path(tmp) / "bb.json"
            scope = _make_scope()
            bb = SrcBlackboard(bb_path)
            bb.ensure()
            for i in range(6):
                bb.timeline_append("fetch", summary=f"GET {i}")
            agent = SrcAgentLoop(AgentConfig(
                blackboard_path=bb_path, scope=scope,
                timeline_keep=2, enable_timeline_compress=False,
            ))
            agent._maybe_compress_timeline()
            snap = bb.snapshot()
            self.assertEqual(0, snap["timeline_head"]["version"])
            self.assertEqual(6, len(snap["timeline"]))

    def test_recall_section_reaches_reasoner(self):
        """A dead-ended target from a past run is recalled for a new same-host intent."""
        with tempfile.TemporaryDirectory() as tmp:
            bb_path = Path(tmp) / "bb.json"
            scope = _make_scope()
            bb = SrcBlackboard(bb_path)
            bb.sync_candidates([{
                "candidate_id": "SC-past", "url": "https://example.com/api/endpoint0",
                "priority": 80, "next_phase": "A-passive-triage",
            }], run_id="past-run")
            past_intent = bb.snapshot()["intents"][0]["intent_id"]
            bb.claim_intent(past_intent, "w0")
            bb.add_dead_end(past_intent, "no_finding_previous_run")
            bb.sync_candidates([{
                "candidate_id": "SC-new", "url": "https://example.com/api/endpoint1",
                "priority": 80, "next_phase": "A-passive-triage",
            }], run_id="new-run")

            prompts: List[Tuple[str, str]] = []

            def capture(system, user, **kw):
                prompts.append((system, user))
                if "Reasoner" in system:
                    return json.dumps({
                        "reasoning": "r", "should_stop": True,
                        "stop_reason": "done", "selected_intents": [],
                    })
                return json.dumps({"analysis": "x", "findings": [], "conclusion": "dead_end"})

            run_src_agent(
                bb_path, scope, max_cycles=1,
                fetcher=lambda url, **kw: (200, "ok", {}),
                llm_complete_fn=capture, worker_id="test-w",
            )
            reasoner_users = [user for system, user in prompts if "Reasoner" in system]
            self.assertTrue(reasoner_users, prompts)
            self.assertIn("Recalled Experience", reasoner_users[0])
            self.assertIn("endpoint0", reasoner_users[0])
            self.assertIn("已失效", reasoner_users[0])


class TestTierRouting(unittest.TestCase):
    """The provider pool must actually route Reasoner→smart, Explorer→cheap."""

    _POOL = [
        {"name": "cheap", "base_url": "https://cheap.test", "api_key": "k-cheap", "model": "mini"},
        {"name": "smart", "base_url": "https://smart.test", "api_key": "k-smart", "model": "max"},
    ]

    def _patched_pool(self, hits: List[Tuple[str, str]]):
        import core.llm_pool as pool

        def fake_post(url, body, api_key, timeout):
            hits.append((url.split("//")[1].split("/")[0], json.loads(body)["model"]))
            return {"choices": [{"message": {"content": "ok"}}]}

        # The agent routes through core.llm_client, which prefers httpx. Blanking
        # the httpx module forces the urllib transport — i.e. the pool._post seam
        # this test mocks. (The httpx transport has its own tests in
        # tests/test_llm_client.py.) Routing is what these tests assert.
        return (pool,
                patch.object(pool, "provider_pool", lambda: list(self._POOL)),
                patch.object(pool, "_post", fake_post),
                patch.dict(sys.modules, {"httpx": None}))

    def test_reasoner_and_explorer_hit_different_providers(self):
        hits: List[Tuple[str, str]] = []
        pool, pool_patch, post_patch, httpx_patch = self._patched_pool(hits)
        with pool_patch, post_patch, httpx_patch:
            with tempfile.TemporaryDirectory() as tmp:
                cfg = AgentConfig(
                    blackboard_path=Path(tmp) / "bb.json", scope=_make_scope(),
                    reasoner_prefer="smart", explorer_prefer="cheap",
                )
                agent = SrcAgentLoop(cfg)
                agent._complete("You are the Reasoner", "u", timeout=1,
                                prefer=cfg.reasoner_prefer, only=cfg.reasoner_only)
                agent._complete("You are the Explorer", "u", timeout=1,
                                prefer=cfg.explorer_prefer, only=cfg.explorer_only)

        self.assertEqual(["smart.test", "cheap.test"], [h[0] for h in hits])
        self.assertEqual(["max", "mini"], [h[1] for h in hits])

    def test_prefer_falls_back_to_other_providers_on_failure(self):
        """prefer only reorders; a dead preferred provider still fails over."""
        hits: List[Tuple[str, str]] = []
        pool, pool_patch, post_patch, httpx_patch = self._patched_pool(hits)

        def flaky_post(url, body, api_key, timeout):
            hits.append((url.split("//")[1].split("/")[0], json.loads(body)["model"]))
            if "smart.test" in url:
                raise OSError("boom")
            return {"choices": [{"message": {"content": "ok"}}]}

        with pool_patch, patch.object(pool, "_post", flaky_post), httpx_patch:
            text = pool.complete("s", "u", timeout=1, prefer="smart")

        self.assertEqual("ok", text)
        self.assertEqual(["smart.test", "cheap.test"], [h[0] for h in hits])

    def test_only_restricts_to_the_matched_provider(self):
        hits: List[Tuple[str, str]] = []
        pool, pool_patch, post_patch, httpx_patch = self._patched_pool(hits)
        with pool_patch, post_patch, httpx_patch:
            self.assertIsNone(pool.complete("s", "u", timeout=1, prefer="no-such-model", only=True))
        self.assertEqual([], hits)

    def test_empty_pool_returns_none(self):
        import core.llm_pool as pool
        with patch.object(pool, "provider_pool", lambda: []):
            self.assertIsNone(pool.complete("s", "u", timeout=1))


class TestFetchGate(unittest.TestCase):
    """闸门顺序:在范围内 → 方法已声明 → body 已声明 → 不是改状态 URL → 限速 → 发。

    以前只有三道(scope / 只读 URL / 限速),而且没有任何地方说得出"这份授权允许
    做什么" —— 只读是源码里的一个常量。
    """

    def test_a_post_is_refused_by_a_read_only_scope(self):
        result = _fetch_for_analysis("https://example.com/api/v1/items", _make_scope(),
                                     method="POST", body="q=1")
        self.assertEqual("method_not_allowed:POST", result["error"])
        self.assertEqual("POST", result["method"])
        self.assertEqual(0, result["status"])

    def test_a_declared_method_without_a_declared_body_is_refused(self):
        """"可以发 POST"和"可以发任意 body"是两件事。"""
        scope = _make_scope(allowed_methods=("POST",))
        result = _fetch_for_analysis("https://example.com/api/v1/items", scope,
                                     method="POST", body="q=1")
        self.assertEqual("body_not_allowed", result["error"])

    def test_an_out_of_scope_url_is_refused_before_the_method_check(self):
        """顺序有意义:范围错了就不该继续往下问方法。"""
        scope = _make_scope(allowed_methods=("POST",), allow_request_body=True)
        result = _fetch_for_analysis("https://evil.com/x", scope, method="POST", body="q=1")
        self.assertIn("scope_rejected", result["error"])
        self.assertEqual("POST", result["method"])

    def test_a_declared_post_goes_through_the_second_seam(self):
        """探测档里唯一能走的 POST:端点自己用读选择器声明了它是读。"""
        seen: List[Tuple] = []

        def requester(method, url, **kwargs):
            seen.append((method, url, kwargs.get("body"), kwargs.get("content_type")))
            return 200, '{"ok": true}', {"content-type": "application/json"}

        scope = _make_scope(allowed_methods=("POST",), allow_request_body=True)
        result = _fetch_for_analysis("https://example.com/api/v1/items?action=query", scope,
                                     method="POST",
                                     body='{"q": 1}', content_type="application/json",
                                     requester=requester)
        self.assertEqual("", result["error"])
        self.assertEqual("POST", result["method"])
        self.assertEqual(200, result["status"])
        self.assertEqual([("POST", "https://example.com/api/v1/items?action=query",
                           b'{"q": 1}', "application/json")], seen)

    def test_an_unproven_post_never_reaches_the_seam(self):
        """没有读证明的 POST 一律拒 —— 空 body 也不是证明(POST /logout 就没有 body)。"""
        seen: List[str] = []

        def requester(method, url, **kwargs):
            seen.append(method)
            return 200, "{}", {}

        scope = _make_scope(allowed_methods=("POST",), allow_request_body=True)
        for body in ('{"q": 1}', ""):
            with self.subTest(body=body):
                result = _fetch_for_analysis("https://example.com/api/v1/items", scope,
                                             method="POST", body=body,
                                             content_type="application/json",
                                             requester=requester)
                self.assertEqual("probe_not_proven_non_mutating", result["error"])
                self.assertEqual(0, result["status"])
        self.assertEqual([], seen, "被拒的请求绝不能碰到传输层")

    def test_a_head_never_becomes_a_get(self):
        """以前 HEAD 是"校验通过之后按 GET 执行" —— 审计行写 GET,实际不是。"""
        seen: List[str] = []

        def requester(method, url, **kwargs):
            seen.append(method)
            return 200, "", {}

        result = _fetch_for_analysis("https://example.com/", _make_scope(),
                                     method="HEAD", requester=requester)
        self.assertEqual(["HEAD"], seen)
        self.assertEqual("HEAD", result["method"])

    def test_get_still_uses_the_injected_fetcher_untouched(self):
        """一堆测试注入的是 GET 形状的 fetcher;这个接缝的签名不能动。"""
        calls: List[str] = []

        def fetcher(url, **kwargs):
            calls.append(url)
            return 200, "ok", {}

        scope = _make_scope(allowed_methods=("POST",), allow_request_body=True)
        result = _fetch_for_analysis("https://example.com/api/v1/items", scope, fetcher=fetcher)
        self.assertEqual(["https://example.com/api/v1/items"], calls)
        self.assertEqual("GET", result["method"])

    def test_every_result_says_which_method_ran(self):
        for call in (
            dict(url="https://evil.com/x"),
            dict(url="https://example.com/api/deleteUser"),   # 改状态 URL,硬拦
            dict(url="https://example.com/api/v1/items", method="POST"),
        ):
            with self.subTest(**call):
                result = _fetch_for_analysis(call.pop("url"), _make_scope(), **call)
                self.assertNotEqual("", result["method"])
                self.assertIn("error", result)


class TestWriteGate(unittest.TestCase):
    """治理语义:写操作是**硬拒**,不是"降级成警告"。

    这里改过一次方向,记下来免得又转回去。原来的规则是"文档声明了写方法之后,
    URL 里那点改状态的味道就从墙降级成警告"——控制点从"URL 有没有某个词"换成
    "操作员签了什么"。听着对,但它放过了 ``GET /logout`` 和 ``GET /api/deleteUser``:
    "禁止任何增删改数据/配置的写操作"说的是这个操作**做什么**,不是哪个动词载着它。
    所以现在:声明写方法什么都放开不了,改状态形状一律拒。
    """

    def test_the_word_list_still_blocks_while_nothing_is_declared(self):
        scope = _make_scope()
        for url in ("https://example.com/api/deleteUser",
                    "https://example.com/api/UpdateStatus",
                    "https://example.com/api/DropDownOptions"):
            with self.subTest(url=url):
                self.assertEqual("state_changing_endpoint",
                                 _fetch_for_analysis(url, scope)["error"])

    def test_declaring_a_write_method_does_not_open_a_state_changing_url(self):
        """声明 POST 不会让 ``GET /api/deleteUser`` 变成可以发的东西。"""
        cases = [
            ("GET", _make_scope(allowed_methods=("POST",)), ""),
            ("POST", _make_scope(allowed_methods=("POST",), allow_request_body=True), "id=1"),
        ]
        for method, scope, body in cases:
            with self.subTest(method=method):
                seen: List[str] = []

                def requester(verb, url, **kwargs):
                    seen.append(verb)
                    return 200, "{}", {}

                result = _fetch_for_analysis("https://example.com/api/deleteUser", scope,
                                             method=method, body=body,
                                             requester=requester)
                self.assertEqual("state_changing_endpoint", result["error"])
                self.assertEqual(0, result["status"])
                self.assertEqual([], seen, "被拒的请求绝不能碰到传输层")

    def test_an_operation_selector_stays_blocked_even_with_write_methods(self):
        """``?action=sendEmail`` 说的是"这个 URL 自己会挑一个操作" —— 方法授权覆盖不了它。"""
        scope = _make_scope(allowed_methods=("POST",), allow_request_body=True)
        result = _fetch_for_analysis("https://example.com/api/x?action=sendEmail", scope,
                                     method="POST", body="to=a@b.c",
                                     requester=lambda *a, **k: (200, "{}", {}))
        self.assertEqual("unknown_operation_selector", result["error"])

    def test_a_selector_that_names_a_method_is_not_a_read_proof(self):
        """``?_method=POST`` 是**写声明**,不是读证明 —— 旧的豁免没了。

        以前它被当成"这个 URL 自己点名了一个方法,而那份方法被声明过",于是可以发。
        但一个要把自己变成 POST 的 URL 说的是"我要写",把它当通行证是把方向读反了。
        """
        seen: List[str] = []

        def requester(method, url, **kwargs):
            seen.append(method)
            return 200, "{}", {}

        for selector in ("POST", "DELETE"):
            with self.subTest(selector=selector):
                scope = _make_scope(allowed_methods=("POST",), allow_request_body=True)
                result = _fetch_for_analysis(f"https://example.com/api/x?_method={selector}",
                                             scope, method="POST", body="a=1",
                                             requester=requester)
                self.assertEqual("unknown_operation_selector", result["error"])
        self.assertEqual([], seen, "被拒的请求绝不能碰到传输层")

    def test_a_read_selector_is_what_opens_the_probe_tier(self):
        """正面形式:``?action=query`` 声明的是一个读操作,这才是可以放行的证明。"""
        seen: List[Tuple] = []

        def requester(method, url, **kwargs):
            seen.append((method, kwargs.get("body")))
            return 200, "{}", {}

        scope = _make_scope(allowed_methods=("POST",), allow_request_body=True)
        result = _fetch_for_analysis("https://example.com/api/x?action=query", scope,
                                     method="POST", body="a=1", requester=requester)
        self.assertEqual("", result["error"])
        self.assertEqual([("POST", b"a=1")], seen)

    def test_every_refusal_keeps_the_transport_untouched(self):
        """红线:被治理拒掉的请求一个都不许发出去 —— 每一种拒绝都过一遍。"""
        seen: List[str] = []

        def fetcher(url, **kwargs):
            seen.append(url)
            return 200, "{}", {}

        def requester(method, url, **kwargs):
            seen.append(url)
            return 200, "{}", {}

        cases = [
            ("https://example.com/api/deleteUser", _make_scope(), "GET", ""),
            ("https://example.com/api/x?action=ping", _make_scope(), "GET", ""),
            ("https://example.com/api/users", _make_scope(), "POST", "a=1"),
            ("https://example.com/api/users", _make_scope(allowed_methods=("PUT",),
                                                          allow_request_body=True), "PUT", "a=1"),
            ("https://example.com/api/users", _make_scope(allowed_methods=("PATCH",),
                                                          allow_request_body=True), "PATCH", "a=1"),
            ("https://example.com/api/users", _make_scope(allowed_methods=("DELETE",)), "DELETE", ""),
        ]
        for url, scope, method, body in cases:
            with self.subTest(url=url, method=method):
                result = _fetch_for_analysis(url, scope, method=method, body=body,
                                             fetcher=fetcher, requester=requester)
                self.assertNotEqual("", result["error"], f"{method} {url} 应该被拒")
                self.assertEqual(0, result["status"])
        self.assertEqual([], seen, "任何一种拒绝都不许碰到传输层")

    def test_a_selector_naming_an_undeclared_method_is_still_blocked(self):
        scope = _make_scope(allowed_methods=("POST",), allow_request_body=True)
        result = _fetch_for_analysis("https://example.com/api/x?_method=DELETE", scope,
                                     method="POST", body="a=1",
                                     requester=lambda *a, **k: (200, "{}", {}))
        self.assertEqual("unknown_operation_selector", result["error"])

    def test_the_signals_reach_the_blackboard(self):
        """标记要跟着候选走到意图上 —— 否则提示词里那节没有来源。"""
        with tempfile.TemporaryDirectory() as tmp:
            board = SrcBlackboard(Path(tmp) / "bb.json", default_lease_seconds=60)
            board.sync_candidates([
                {"candidate_id": "SC-1", "priority": 80, "url": "https://example.com/api/deleteUser"},
                {"candidate_id": "SC-2", "priority": 70, "url": "https://example.com/api/users"},
            ], run_id="SA-1")
            snapshot = board.snapshot()
        marks = {row["target"]: row["state_changing_endpoint"] for row in snapshot["intents"]}
        self.assertIs(True, marks["https://example.com/api/deleteUser"])
        self.assertIs(False, marks["https://example.com/api/users"])

    def test_a_change_shaped_url_never_reaches_the_explorer(self):
        """"这次是改动不是读取"那句提示删掉了 —— 它现在不可达。

        改状态形状的 URL 在闸门就被拒,Explorer 根本不会为它运行,所以再给模型一句
        "发之前确认这就是你要的改动"只会教它去做一件做不到的事。
        """
        self.assertEqual("", _shape_signals_section([], "https://example.com/api/deleteUser"))
        self.assertEqual("", _shape_signals_section([], "https://example.com/api/users"))
        # 形状先验本身还在,只是不再有"这是改动"那一类。
        self.assertIn("idor", _shape_signals_section(["idor"], "https://example.com/api/users"))

    def test_no_decision_is_named_write_blocked_any_more(self):
        """四个原因各说各的:方法 / body / 改状态端点 / 操作选择器。"""
        read_only = _make_scope()
        writable = _make_scope(allowed_methods=("POST",))
        cases = {
            "method_not_allowed:POST": (
                read_only, "https://example.com/api/users", dict(method="POST", body="a=1")),
            "body_not_allowed": (
                writable, "https://example.com/api/users", dict(method="POST", body="a=1")),
            "state_changing_endpoint": (
                read_only, "https://example.com/api/deleteUser", {}),
            "unknown_operation_selector": (
                read_only, "https://example.com/api/x?action=ping", {}),
        }
        for expected, (scope, url, call) in cases.items():
            with self.subTest(expected=expected):
                result = _fetch_for_analysis(
                    url, scope, requester=lambda *a, **k: (200, "{}", {}), **call)
                self.assertEqual(expected, result["error"])
                self.assertNotIn("write_blocked", result["error"])


class TestHttpActionAudit(unittest.TestCase):
    """非读动作:完整记录落 run 目录,黑板只留指纹。

    黑板的去敏只有一个弱正则(core.src_blackboard._SECRET_TEXT),拿它当"请求体
    不会外泄"的保证是不成立的 —— 所以请求体只写进 http-actions.jsonl。
    """

    def test_a_post_body_is_audited_in_full_and_only_fingerprinted_on_the_blackboard(self):
        # 一个黑板的弱正则**认不出来**的标记 —— 这才是"请求体只进审计文件"的诚实检验。
        # 用可放行的 GraphQL 读请求,因为现在探测档只放行能正面证明是读的 POST。
        secret = '{"query": "{ viewer { id } }", "variables": {"cursor": "XSECRETMARKERX"}}'

        with tempfile.TemporaryDirectory() as tmp:
            bb_path = Path(tmp) / "bb.json"
            bb = SrcBlackboard(bb_path)
            bb.sync_candidates([{"candidate_id": "SC-1", "priority": 80,
                                 "url": "https://example.com/api/v1/items"}], run_id="SA-1")
            intent_id = bb.snapshot()["intents"][0]["intent_id"]
            rounds = {"n": 0}

            def complete(system, user, **kw):
                if "Reasoner" in system:
                    return json.dumps({"reasoning": "t", "should_stop": False,
                                       "selected_intents": [{"intent_id": intent_id,
                                                             "hypothesis": "h", "check_description": "c"}]})
                rounds["n"] += 1
                if rounds["n"] == 1:
                    return json.dumps({
                        "analysis": "x", "findings": [], "conclusion": "inconclusive",
                        "http_actions": [{"method": "POST", "url": "https://example.com/api/graphql",
                                          "body": secret, "reason": "probe",
                                          "content_type": "application/json"}],
                    })
                return json.dumps({"analysis": "x", "findings": [], "conclusion": "dead_end",
                                   "dead_end_reason": "n"})

            scope = _make_scope(allowed_methods=("POST",), allow_request_body=True)
            run_src_agent(bb_path, scope, max_cycles=2,
                          fetcher=lambda url, **kw: (200, "{}", {}),
                          requester=lambda method, url, **kw: (200, '{"ok": true}',
                                                               {"content-type": "application/json"}),
                          llm_complete_fn=complete, worker_id="test-w")

            audit = Path(tmp) / HTTP_ACTION_LOG
            self.assertTrue(audit.is_file(), "非读动作没有落审计")
            rows = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines() if line.strip()]
            actions = [row for row in rows if row["kind"] == "action"]
            self.assertEqual(1, len(actions))
            self.assertEqual("POST", actions[0]["method"])
            self.assertEqual("allowed", actions[0]["decision"])
            self.assertEqual(secret, actions[0]["request_body"])       # 全文只在这一个文件里
            self.assertEqual(12, len(actions[0]["request"]["sha256_12"]))
            # 每一次出站都要有记录:探索前的第一跳以前只进时间线、不进这份日志。
            self.assertTrue(any(row["kind"] == "intent_fetch" for row in rows),
                            "intent 首取也是真实出站,必须留痕")

            board_text = bb_path.read_text(encoding="utf-8")
            self.assertNotIn(secret, board_text)
            self.assertNotIn("XSECRETMARKERX", board_text)
            self.assertIn("sha256=", board_text)                       # 指纹进了时间线

    def test_a_refused_action_is_still_audited(self):
        """被拦下来的那次尝试本身就是要审计的东西 —— 不然"谁试过什么"没有记录。"""
        with tempfile.TemporaryDirectory() as tmp:
            bb_path = Path(tmp) / "bb.json"
            bb = SrcBlackboard(bb_path)
            bb.sync_candidates([{"candidate_id": "SC-1", "priority": 80,
                                 "url": "https://example.com/api/v1/items"}], run_id="SA-1")
            intent_id = bb.snapshot()["intents"][0]["intent_id"]
            rounds = {"n": 0}

            def complete(system, user, **kw):
                if "Reasoner" in system:
                    return json.dumps({"reasoning": "t", "should_stop": False,
                                       "selected_intents": [{"intent_id": intent_id,
                                                             "hypothesis": "h", "check_description": "c"}]})
                rounds["n"] += 1
                if rounds["n"] == 1:
                    return json.dumps({
                        "analysis": "x", "findings": [], "conclusion": "inconclusive",
                        "http_actions": [{"method": "DELETE",
                                          "url": "https://example.com/api/v1/items",
                                          "reason": "try it"}],
                    })
                return json.dumps({"analysis": "x", "findings": [], "conclusion": "dead_end",
                                   "dead_end_reason": "n"})

            run_src_agent(bb_path, _make_scope(), max_cycles=2,
                          fetcher=lambda url, **kw: (200, "{}", {}),
                          llm_complete_fn=complete, worker_id="test-w")

            rows = [json.loads(line) for line in
                    (Path(tmp) / HTTP_ACTION_LOG).read_text(encoding="utf-8").splitlines() if line.strip()]
            actions = [row for row in rows if row["kind"] == "action"]
            self.assertEqual(1, len(actions))
            self.assertEqual("DELETE", actions[0]["method"])
            self.assertEqual(0, actions[0]["status"])
            # 拒绝理由进记录,而且说清是"破坏性方法"而不是"你没声明它"。
            self.assertEqual("refused:destructive_method_forbidden", actions[0]["decision"])


class TestCapabilityInPrompt(unittest.TestCase):
    """模型看到的 = 沙箱会执行的,两边同一份来源。

    角色契约以前硬编码"只能 GET/HEAD,不能发 POST":默认成立,一旦 scope 声明了
    更多就是谎话。告诉模型"不能 POST"而沙箱其实放行,它永远不会试;反过来告诉它
    "能"而沙箱拒掉,它写出来的计划全在闸门那儿死掉。
    """

    def _loop(self, tmp, **scope_kwargs):
        config = AgentConfig(blackboard_path=Path(tmp) / "bb.json", scope=_make_scope(**scope_kwargs))
        return SrcAgentLoop(config)

    def test_a_read_only_scope_says_so(self):
        with tempfile.TemporaryDirectory() as tmp:
            prompt = self._loop(tmp)._system(REASONER_SYSTEM)
        self.assertIn("允许的方法: GET, HEAD", prompt)
        self.assertIn("只有只读方法", prompt)
        self.assertNotIn("{capabilities}", prompt)

    def test_a_writable_scope_says_what_is_allowed(self):
        """提示词只能广告闸门真会发的方法。PUT 被声明了但恒拒,必须说出来。"""
        with tempfile.TemporaryDirectory() as tmp:
            loop = self._loop(tmp, allowed_methods=("POST", "PUT"), allow_request_body=True)
            prompt = loop._system(EXPLORER_SYSTEM)
        self.assertIn("允许的方法: GET, HEAD, POST", prompt)
        self.assertIn("可以带请求体", prompt)
        self.assertIn("一律会被拒: PUT", prompt)
        self.assertNotIn("{capabilities}", prompt)

    def test_a_writable_scope_without_a_body_channel_says_that_too(self):
        with tempfile.TemporaryDirectory() as tmp:
            loop = self._loop(tmp, allowed_methods=("POST",))
            prompt = loop._system(REASONER_SYSTEM)
        self.assertIn("不允许带请求体", prompt)

    def test_the_prompt_line_comes_from_the_scope_itself(self):
        with tempfile.TemporaryDirectory() as tmp:
            loop = self._loop(tmp, allowed_methods=("POST",), allow_request_body=True)
            self.assertIn(loop.config.scope.capability_line(), loop._system(REASONER_SYSTEM))

    def test_the_sandbox_limit_is_not_hardcoded_in_the_prompt(self):
        with tempfile.TemporaryDirectory() as tmp:
            prompt = self._loop(tmp)._system(EXPLORER_SYSTEM)
        from agents.src_agent import MAX_HTTP_ACTIONS

        self.assertIn(f"上限 {MAX_HTTP_ACTIONS} 个", prompt)

    def test_capabilities_can_be_left_alone_for_a_custom_base(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw = self._loop(tmp)._system("BASE {capabilities}", capabilities=False)
        self.assertIn("{capabilities}", raw)


class TestLlmBudget(unittest.TestCase):
    """一次 token 上限就是整个 hunt 死掉的原因,所以这个数必须被钉住。

    2026-09-21:``max_tokens=2048`` + deepseek-flash 默认开思考 → 真实 Reasoner 提示词下
    ``content`` 返回 0 字符,``reasoner_returned_none``,``cycles_run: 1``、0 个候选被看过。
    """

    def setUp(self):
        import agents.src_agent as mod

        self.mod = mod
        self._saved = os.environ.get(mod.LLM_MAX_TOKENS_ENV)

    def tearDown(self):
        if self._saved is None:
            os.environ.pop(self.mod.LLM_MAX_TOKENS_ENV, None)
        else:
            os.environ[self.mod.LLM_MAX_TOKENS_ENV] = self._saved

    def test_the_default_budget_leaves_room_for_thinking_plus_json(self):
        os.environ.pop(self.mod.LLM_MAX_TOKENS_ENV, None)
        self.assertEqual(self.mod.DEFAULT_LLM_MAX_TOKENS, self.mod.configured_max_tokens())
        self.assertGreater(self.mod.configured_max_tokens(), 2048,
                           "回到 2048 就是回到 thinking 吃光预算、content 为空")

    def test_the_budget_can_be_overridden_for_another_model(self):
        os.environ[self.mod.LLM_MAX_TOKENS_ENV] = "4096"
        self.assertEqual(4096, self.mod.configured_max_tokens())

    def test_garbage_falls_back_instead_of_disabling_the_cap(self):
        for bad in ("", "  ", "lots", "0", "-1"):
            os.environ[self.mod.LLM_MAX_TOKENS_ENV] = bad
            self.assertGreaterEqual(self.mod.configured_max_tokens(), 256, f"输入 {bad!r}")

    def test_an_empty_content_reply_says_why_instead_of_just_none(self):
        """空 content 不能再是一个无声的 None —— 那正是这个 bug 藏了两天的原因。"""
        import agents.src_agent as mod

        fake = {"role": "assistant", "content": "",
                "reasoning_content": "x" * 5000}
        with patch("core.llm_client.complete_messages", return_value=fake):
            self.assertIsNone(mod._default_llm_complete("s", "u"))

        reason = mod.last_llm_error()
        self.assertIn("empty content", reason)
        self.assertIn("5000", reason, "要带上 reasoning_content 长度,否则没法判断是不是思考吃光了")
        self.assertIn(mod.LLM_MAX_TOKENS_ENV, reason, "要给出可操作的那一步")


class TestRequestBudget(unittest.TestCase):
    """一轮能发多少请求。红线要求"最小化",而在这之前没有任何计数器。"""

    def _reasoner(self, intent_id):
        def complete(system, user, **kwargs):
            if "Reasoner" in system:
                return json.dumps({
                    "reasoning": "t", "should_stop": False,
                    "selected_intents": [{"intent_id": intent_id,
                                          "hypothesis": "h", "check_description": "c"}],
                })
            return json.dumps({"analysis": "x", "findings": [],
                               "conclusion": "dead_end", "dead_end_reason": "nothing"})
        return complete

    def test_the_budget_caps_the_requests_that_actually_go_out(self):
        from core.rate_limit import RequestBudget

        sent: List[str] = []

        def fetcher(url, **kwargs):
            sent.append(url)
            return 200, "{}", {}

        with tempfile.TemporaryDirectory() as tmp:
            bb_path = Path(tmp) / "bb.json"
            bb = SrcBlackboard(bb_path)
            _seed_blackboard(bb, 4)
            ids = [row["intent_id"] for row in bb.snapshot()["intents"]]

            def complete(system, user, **kwargs):
                if "Reasoner" in system:
                    return json.dumps({
                        "reasoning": "t", "should_stop": False,
                        "selected_intents": [{"intent_id": item, "hypothesis": "h",
                                              "check_description": "c"} for item in ids],
                    })
                return json.dumps({"analysis": "x", "findings": [],
                                   "conclusion": "dead_end", "dead_end_reason": "nothing"})

            summary = run_src_agent(bb_path, _make_scope(), max_cycles=6,
                                    request_budget=RequestBudget(2),
                                    fetcher=fetcher, llm_complete_fn=complete,
                                    worker_id="test-w")

        self.assertEqual(2, len(sent), "额度是 2 就是只能出去 2 个请求")
        self.assertEqual(2, summary["requests_used"])
        self.assertEqual(2, summary["request_budget"])
        self.assertEqual("request_budget_exhausted", summary["stop_reason"])

    def test_a_run_without_a_budget_still_gets_one(self):
        """缺省也要有上限 —— 红线不该只对"特意传了预算"的调用方生效。"""
        from core.rate_limit import MAX_REQUESTS_PER_RUN

        with tempfile.TemporaryDirectory() as tmp:
            bb_path = Path(tmp) / "bb.json"
            bb = SrcBlackboard(bb_path)
            _seed_blackboard(bb, 1)
            iid = bb.snapshot()["intents"][0]["intent_id"]
            summary = run_src_agent(bb_path, _make_scope(), max_cycles=1,
                                    fetcher=lambda url, **kw: (200, "{}", {}),
                                    llm_complete_fn=self._reasoner(iid), worker_id="test-w")

        self.assertEqual(MAX_REQUESTS_PER_RUN, summary["request_budget"])
        self.assertGreater(summary["requests_used"], 0)

    def test_a_governance_refusal_is_terminal_on_the_first_attempt(self):
        """重试还是同一个结果,所以不该被重排队 —— 那等于白烧 LLM 调用和圈数。"""
        with tempfile.TemporaryDirectory() as tmp:
            bb_path = Path(tmp) / "bb.json"
            bb = SrcBlackboard(bb_path)
            bb.sync_candidates([{
                "candidate_id": "SC-1", "priority": 90,
                "url": "https://example.com/api/deleteUser",
            }], run_id="SA-1")
            iid = bb.snapshot()["intents"][0]["intent_id"]
            sent: List[str] = []

            def fetcher(url, **kwargs):
                sent.append(url)
                return 200, "{}", {}

            run_src_agent(bb_path, _make_scope(), max_cycles=4,
                          fetcher=fetcher, llm_complete_fn=self._reasoner(iid),
                          worker_id="test-w")
            intent = next(row for row in bb.snapshot()["intents"] if row["intent_id"] == iid)
            timeline = [row.get("kind") for row in bb.snapshot().get("timeline", [])]

        self.assertEqual([], sent, "改状态形状的 URL 一个请求都不该发出去")
        self.assertEqual("dead_end", intent["status"])
        self.assertLessEqual(intent["attempts"], 1, "治理拒绝最多算一次尝试")
        self.assertIn("refused", timeline)


class TestRouteReflow(unittest.TestCase):
    """Explorer 在响应里看见的路由,要能变成下一轮的可选候选。

    在这之前清单在第 1 圈就冻结了:``sync_candidates`` 只在 surface discovery 之后被喂过
    一次,响应能**关闭**一个 intent,永远不能**打开**一个。真机实证:模型自己推出了
    「``/admin`` 和 ``/openidm/console`` 到了源站,``/console`` 被边缘吞掉」,写进 hint,
    然后就停在那里 —— 有直觉,没有手。
    """

    TARGET = "https://example.com/api/endpoint0"
    ROUTE = "/openidm/config/managed"

    def _reasoner_selecting_all(self, bb, routes):
        """Reasoner 每轮选中所有 queued intent;Explorer 只在第一轮报路由。

        ``routes`` 必须传进来 —— 闭包是词法的,测试方法里的局部变量在这里不可见。
        """
        def complete(system, user, **kwargs):
            if "Reasoner" in system:
                ids = [row["intent_id"] for row in bb.snapshot()["intents"]
                       if row.get("status") == "queued"]
                return json.dumps({
                    "reasoning": "t", "should_stop": False,
                    "selected_intents": [{"intent_id": item, "hypothesis": "h",
                                          "check_description": "c"} for item in ids],
                })
            parsed = {"analysis": "x", "findings": [], "conclusion": "dead_end",
                      "dead_end_reason": "nothing"}
            if routes["round"] == 0:
                parsed["discovered_routes"] = routes["value"]
            routes["round"] += 1
            return json.dumps(parsed)
        return complete

    def test_a_reported_route_becomes_an_intent_and_gets_explored(self):
        routes = {"round": 0, "value": [self.ROUTE]}
        sent: List[str] = []

        def fetcher(url, **kwargs):
            sent.append(url)
            return 200, "{}", {}

        with tempfile.TemporaryDirectory() as tmp:
            bb_path = Path(tmp) / "bb.json"
            bb = SrcBlackboard(bb_path)
            _seed_blackboard(bb, 1)
            summary = run_src_agent(bb_path, _make_scope(), max_cycles=3,
                                    fetcher=fetcher,
                                    llm_complete_fn=self._reasoner_selecting_all(bb, routes),
                                    worker_id="test-w")
            urls = {row["target"] for row in bb.snapshot()["intents"]}

        self.assertEqual(1, summary["intents_from_routes"])
        self.assertIn("https://example.com/openidm/config/managed", urls,
                      "报的路由没有变成 intent —— 清单还是冻结的")
        self.assertIn("https://example.com/openidm/config/managed", sent,
                      "新 intent 没有被真的探索")

    def test_the_same_route_twice_is_one_intent(self):
        """同一个 URL 从不同轮/不同意图报出来,不能变成两条。"""
        routes = {"round": 0, "value": [self.ROUTE, self.ROUTE, " " + self.ROUTE + " "]}
        with tempfile.TemporaryDirectory() as tmp:
            bb_path = Path(tmp) / "bb.json"
            bb = SrcBlackboard(bb_path)
            _seed_blackboard(bb, 2)
            summary = run_src_agent(bb_path, _make_scope(), max_cycles=2,
                                    fetcher=lambda url, **kw: (200, "{}", {}),
                                    llm_complete_fn=self._reasoner_selecting_all(bb, routes),
                                    worker_id="test-w")
            intents = bb.snapshot()["intents"]
        urls = [row["target"] for row in intents]
        self.assertEqual(1, urls.count("https://example.com/openidm/config/managed"), urls)
        self.assertLessEqual(summary["intents_from_routes"], 1)

    def test_a_route_outside_the_scope_is_dropped_and_counted(self):
        """模型报什么都不增加授权 —— 主机轴还是操作员签的那份。"""
        routes = {"round": 0, "value": ["https://evil.example/config/x"]}
        with tempfile.TemporaryDirectory() as tmp:
            bb_path = Path(tmp) / "bb.json"
            bb = SrcBlackboard(bb_path)
            _seed_blackboard(bb, 1)
            summary = run_src_agent(bb_path, _make_scope(), max_cycles=2,
                                    fetcher=lambda url, **kw: (200, "{}", {}),
                                    llm_complete_fn=self._reasoner_selecting_all(bb, routes),
                                    worker_id="test-w")
            urls = {row["target"] for row in bb.snapshot()["intents"]}
            timeline = [str(row.get("kind")) for row in bb.snapshot().get("timeline", [])]

        self.assertEqual(0, summary["intents_from_routes"])
        self.assertNotIn("https://evil.example/config/x", urls)
        self.assertIn("route_dropped", timeline)

    def test_the_per_cycle_cap_holds(self):
        many = [f"/openidm/config/thing{i}" for i in range(40)]
        routes = {"round": 0, "value": many}
        with tempfile.TemporaryDirectory() as tmp:
            bb_path = Path(tmp) / "bb.json"
            bb = SrcBlackboard(bb_path)
            _seed_blackboard(bb, 1)
            run_src_agent(bb_path, _make_scope(), max_cycles=1,
                          fetcher=lambda url, **kw: (200, "{}", {}),
                          llm_complete_fn=self._reasoner_selecting_all(bb, routes),
                          worker_id="test-w")
            intent_count = len(bb.snapshot()["intents"])
        self.assertLessEqual(intent_count, 1 + MAX_ROUTE_PROPOSALS_PER_CYCLE)

    def test_the_converter_is_the_same_one_candidates_use(self):
        """同一个 URL,提取来的和报来的必须是同一条 —— 否则两套会打架。"""
        from agents.src_autopilot import _candidate_id, candidate_from_route

        scope = _make_scope()
        bound = candidate_from_route(self.ROUTE, scope, base_url=self.TARGET)
        self.assertIsNotNone(bound)
        self.assertEqual("https://example.com/openidm/config/managed", bound["url"])
        self.assertEqual(_candidate_id(bound["url"]), bound["candidate_id"])
        self.assertEqual(["explorer-route"], bound["sources"])

    def test_the_converter_refuses_an_out_of_scope_route(self):
        from agents.src_autopilot import candidate_from_route

        self.assertIsNone(candidate_from_route("https://evil.example/x", _make_scope(),
                                               base_url=self.TARGET))


if __name__ == "__main__":
    unittest.main()
