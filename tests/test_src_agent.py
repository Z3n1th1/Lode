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
    ExploreResult,
    SrcAgentLoop,
    AgentConfig,
    EXPLORER_SYSTEM,
    REASONER_SYSTEM,
    _blackboard_to_context,
    _fetch_for_analysis,
    _parse_json_response,
    _sanitize_headers,
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
        scope = _make_scope()
        result = _fetch_for_analysis("https://example.com/api/deleteUser", scope)
        self.assertIn("write_blocked", result["error"])

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


if __name__ == "__main__":
    unittest.main()
