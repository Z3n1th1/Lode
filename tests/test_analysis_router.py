"""Specialist routing: Lode decides who may speak; CLIs never get HTTP."""
from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT))

from core.analysis_router import (  # noqa: E402
    alternate_engine,
    delegate_analysis,
    high_risk_finding,
    may_delegate,
    route,
)
from agents.src_autopilot import _score_candidate  # noqa: E402
from agents.src_agent import EXPLORER_TOOLS  # noqa: E402


class RoutingTests(unittest.TestCase):
    def test_ordinary_blackbox_stays_on_the_hunter(self) -> None:
        with patch.dict(os.environ, {"LODE_HUNTER_ENGINE": "pi"}, clear=False):
            self.assertEqual("pi", route("blackbox", hunter="pi"))
            self.assertFalse(may_delegate("blackbox"))
            self.assertFalse(may_delegate("conflict"))

    def test_high_risk_review_uses_a_different_model(self) -> None:
        self.assertEqual("claude", route("high_risk_review", original_engine="grok"))
        self.assertEqual("grok", route("high_risk_review", original_engine="pi"))
        self.assertTrue(may_delegate("high_risk_review"))
        self.assertTrue(may_delegate("source_repo"))

    def test_retry_empty_switches_once(self) -> None:
        self.assertEqual("provider", alternate_engine("pi"))
        self.assertEqual("pi", alternate_engine("provider"))

    def test_delegate_refuses_ordinary_blackbox(self) -> None:
        result = delegate_analysis("", "next request", "{}", kind="blackbox")
        self.assertTrue(result["skipped"])
        self.assertEqual("ordinary_blackbox_stays_on_hunter", result["reason"])

    def test_delegate_falls_back_when_the_cli_is_missing(self) -> None:
        with patch("core.cli_engines.complete", return_value=None), \
             patch("core.cli_engines.last_error", return_value="not found"), \
             patch("core.cli_engines.fallback_to_provider", return_value=True), \
             patch("core.llm_client.complete_messages",
                   return_value={"content": json.dumps({
                       "analysis": "ok", "conclusion": "unsupported",
                       "confidence": "high", "evidence": ["none"],
                   })}):
            result = delegate_analysis("grok", "review this", "ctx", kind="high_risk_review")
        self.assertTrue(result["ok"])
        self.assertEqual("provider", result["engine"])
        self.assertEqual("unsupported", result["analysis"]["conclusion"])

    def test_high_risk_finding_detects_rce_shape(self) -> None:
        self.assertTrue(high_risk_finding({"type": "rce", "severity": "high"}))
        self.assertTrue(high_risk_finding({"description": "Conductor 未授权 INLINE"}))
        self.assertFalse(high_risk_finding({"type": "info", "severity": "low"}))


class HunterToolsTests(unittest.TestCase):
    def test_lode_exposes_the_five_controlled_tools(self) -> None:
        names = [item["function"]["name"] for item in EXPLORER_TOOLS]
        self.assertEqual(
            ["read_blackboard", "fetch_url", "read_knowledge",
             "delegate_analysis", "submit_verdict"],
            names,
        )


class HighRiskScoringTests(unittest.TestCase):
    def test_workflow_and_origin_outrank_a_static_asset(self) -> None:
        static = _score_candidate("https://app.example.com/static/app.js", ["html"])
        workflow = _score_candidate(
            "https://hweb-food.example.com/api/workflow/search",
            ["js"],
            ("critical", "high", "rce"),
        )
        origin = _score_candidate(
            "https://pre-admin.example.com/actuator/health",
            ["origin-direct"],
            ("critical", "high", "rce", "orphan_origin"),
        )
        self.assertGreater(workflow, static)
        self.assertGreater(origin, static)
        self.assertGreaterEqual(origin, 70)


if __name__ == "__main__":
    unittest.main()
