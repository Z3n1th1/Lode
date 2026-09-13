"""Tests for core.modes, core.intent_router and core.skills."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "core"))

from core import intent_router, modes, skills  # noqa: E402


class ModesTests(unittest.TestCase):
    def test_loads_the_shipped_modes(self) -> None:
        table = modes.modes()
        for name in ("chat", "ctf", "src_blackbox", "code_audit"):
            self.assertIn(name, table)
        self.assertEqual("CTF", table["ctf"].title)
        self.assertTrue(table["ctf"].may_escalate)
        self.assertFalse(table["chat"].may_escalate)

    def test_unknown_mode_falls_back_to_default(self) -> None:
        self.assertEqual(modes.DEFAULT_MODE, modes.get_mode("nope").name)
        self.assertEqual(modes.DEFAULT_MODE, modes.get_mode("").name)

    def test_list_modes_shape(self) -> None:
        rows = modes.list_modes()
        self.assertTrue(rows)
        first = rows[0]
        for key in ("name", "title", "skill", "tier", "autonomy", "tools"):
            self.assertIn(key, first)

    def test_missing_file_falls_back(self) -> None:
        table = modes.load_modes("/nonexistent/modes.yaml")
        self.assertIn("chat", table)


class IntentRouterTests(unittest.TestCase):
    def test_mode_command_replies_and_switches(self) -> None:
        decision = intent_router.route("进入 CTF 模式", mode=modes.get_mode("chat"))
        self.assertEqual(intent_router.REPLY, decision.action)
        self.assertEqual("ctf", decision.mode)
        self.assertEqual("mode_command", decision.reason)

    def test_url_plus_action_escalates_in_blackbox_mode(self) -> None:
        decision = intent_router.route("扫描一下 https://target.example.com", mode=modes.get_mode("src_blackbox"))
        self.assertTrue(decision.escalates)
        self.assertEqual("src_loop", decision.subtask_kind)
        self.assertEqual("https://target.example.com", decision.target)

    def test_url_does_not_escalate_in_chat_mode(self) -> None:
        decision = intent_router.route("扫描一下 https://target.example.com", mode=modes.get_mode("chat"))
        self.assertEqual(intent_router.REPLY, decision.action)
        self.assertEqual("autonomy_none", decision.reason)

    def test_plain_question_replies(self) -> None:
        decision = intent_router.route("什么是 SSRF？", mode=modes.get_mode("src_blackbox"))
        self.assertEqual(intent_router.REPLY, decision.action)

    def test_url_without_verb_replies(self) -> None:
        decision = intent_router.route("https://example.com 这个站好看吗", mode=modes.get_mode("src_blackbox"))
        self.assertEqual(intent_router.REPLY, decision.action)

    def test_ctf_mode_routes_to_ctf_subtask(self) -> None:
        decision = intent_router.route("扫描一下 http://ctf.local/challenge", mode=modes.get_mode("ctf"))
        self.assertTrue(decision.escalates)
        self.assertEqual("ctf_solve", decision.subtask_kind)

    def test_ambiguous_uses_llm_then_fails_safe(self) -> None:
        # verb without URL -> optional LLM; a None/empty answer must not escalate
        decision = intent_router.route("帮我找找漏洞", mode=modes.get_mode("src_blackbox"),
                                      llm_complete=lambda *a, **k: None)
        self.assertEqual(intent_router.REPLY, decision.action)

    def test_llm_may_escalate_when_confident(self) -> None:
        decision = intent_router.route(
            "帮我找找漏洞", mode=modes.get_mode("src_blackbox"),
            llm_complete=lambda *a, **k: '{"action":"escalate","target":"http://t.local","reason":"ask"}')
        self.assertTrue(decision.escalates)
        self.assertEqual("http://t.local", decision.target)

    def test_empty_text_replies(self) -> None:
        self.assertEqual(intent_router.REPLY,
                         intent_router.route("   ", mode=modes.get_mode("ctf")).action)


class SkillsTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "skills"
        pack = self.root / "demo"
        (pack / "modules").mkdir(parents=True)
        (pack / "SKILL.md").write_text(
            "---\nname: demo\ndescription: a demo pack\n---\n\nDISPATCHER BODY\n", encoding="utf-8")
        (pack / "modules" / "web.md").write_text(
            "---\ndescription: web module\n---\n\nWEB MODULE BODY\n", encoding="utf-8")
        self.addCleanup(self._tmp.cleanup)

    def test_discover_and_load(self) -> None:
        packs = skills.discover(self.root)
        self.assertIn("demo", packs)
        self.assertEqual(["web"], [m.name for m in packs["demo"].modules])
        self.assertEqual("web module", packs["demo"].modules[0].description)

    def test_compose_prompt_with_and_without_modules(self) -> None:
        base = skills.compose_prompt("demo", root=self.root)
        self.assertIn("DISPATCHER BODY", base)
        self.assertNotIn("WEB MODULE BODY", base)
        with_module = skills.compose_prompt("demo", modules=("web",), root=self.root)
        self.assertIn("WEB MODULE BODY", with_module)

    def test_missing_pack_is_empty_not_an_error(self) -> None:
        self.assertEqual("", skills.compose_prompt("nope", root=self.root))
        self.assertEqual([], skills.module_names("nope", root=self.root))

    def test_size_cap(self) -> None:
        text = skills.compose_prompt("demo", root=self.root, max_chars=10)
        self.assertLessEqual(len(text), 10 + len("\n\n[... skill pack truncated ...]"))


if __name__ == "__main__":
    unittest.main()
