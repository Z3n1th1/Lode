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


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        from agents.src_agent import _self_test
        self.assertEqual(_self_test(), 0)


if __name__ == "__main__":
    unittest.main()
