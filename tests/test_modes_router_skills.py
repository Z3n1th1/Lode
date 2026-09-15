"""Tests for core.modes, core.intent_router and core.skills."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "core"))

from agents import tool_registry  # noqa: E402
from core import intent_router, modes, skills  # noqa: E402


class ModesTests(unittest.TestCase):
    def test_loads_the_shipped_modes(self) -> None:
        table = modes.modes()
        self.assertEqual(["chat", "pentest"], list(table))
        self.assertEqual("挖洞", table["pentest"].title)
        self.assertEqual("pentest", table["pentest"].skill)
        self.assertTrue(table["pentest"].may_escalate)
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


class ModeToolDeclarationTests(unittest.TestCase):
    """A mode's declared tools are a promise; these are the only two ways it breaks."""

    def test_the_hunting_mode_declares_only_implemented_tools(self) -> None:
        declared = modes.get_mode("pentest").tools
        schemas, dispatch, missing = tool_registry.resolve(declared)
        self.assertEqual([], missing)
        self.assertEqual(len(declared), len(schemas))
        self.assertIn("scan_target", dispatch)

    def test_yaml_and_fallback_agree_on_tools(self) -> None:
        """config/modes.yaml wins, so editing a tool list in only one place is a bug."""
        from_yaml = {name: list(mode.tools) for name, mode in modes.load_modes().items()}
        fallback = {name: [str(tool) for tool in body["tools"]]
                    for name, body in modes._FALLBACK.items()}
        self.assertEqual(fallback, from_yaml)


class IntentRouterTests(unittest.TestCase):
    def test_mode_command_replies_and_switches(self) -> None:
        decision = intent_router.route("进入挖洞模式", mode=modes.get_mode("chat"))
        self.assertEqual(intent_router.REPLY, decision.action)
        self.assertEqual("pentest", decision.mode)
        self.assertEqual("mode_command", decision.reason)

    def test_other_spellings_of_the_hunting_mode_resolve(self) -> None:
        for command in ("切换到渗透模式", "用 SRC 模式", "开启黑盒模式"):
            with self.subTest(command=command):
                decision = intent_router.route(command, mode=modes.get_mode("chat"))
                self.assertEqual("pentest", decision.mode)

    def test_a_removed_mode_command_is_inert(self) -> None:
        """CTF / code-audit left the product: their commands must not land somewhere.

        They fall through to a plain reply, and an unknown mode name resolves to
        the default mode rather than raising.
        """
        decision = intent_router.route("进入 CTF 模式", mode=modes.get_mode("pentest"))
        self.assertEqual(intent_router.REPLY, decision.action)
        self.assertEqual("default_reply", decision.reason)
        self.assertEqual(modes.DEFAULT_MODE, modes.get_mode("ctf").name)
        self.assertEqual(modes.DEFAULT_MODE, modes.get_mode("code_audit").name)

    def test_url_plus_action_escalates_in_the_hunting_mode(self) -> None:
        decision = intent_router.route("扫描一下 https://target.example.com", mode=modes.get_mode("pentest"))
        self.assertTrue(decision.escalates)
        self.assertEqual("src_loop", decision.subtask_kind)
        self.assertEqual("https://target.example.com", decision.target)

    def test_url_does_not_escalate_in_chat_mode(self) -> None:
        decision = intent_router.route("扫描一下 https://target.example.com", mode=modes.get_mode("chat"))
        self.assertEqual(intent_router.REPLY, decision.action)
        self.assertEqual("autonomy_none", decision.reason)

    def test_plain_question_replies(self) -> None:
        decision = intent_router.route("什么是 SSRF？", mode=modes.get_mode("pentest"))
        self.assertEqual(intent_router.REPLY, decision.action)

    def test_url_without_verb_replies(self) -> None:
        decision = intent_router.route("https://example.com 这个站好看吗", mode=modes.get_mode("pentest"))
        self.assertEqual(intent_router.REPLY, decision.action)

    def test_the_hunting_mode_always_routes_to_the_blackbox_loop(self) -> None:
        decision = intent_router.route("扫描一下 http://target.local/app",
                                       mode=modes.get_mode("pentest"))
        self.assertTrue(decision.escalates)
        self.assertEqual("src_loop", decision.subtask_kind)

    def test_ambiguous_uses_llm_then_fails_safe(self) -> None:
        # verb without URL -> optional LLM; a None/empty answer must not escalate
        decision = intent_router.route("帮我找找漏洞", mode=modes.get_mode("pentest"),
                                      llm_complete=lambda *a, **k: None)
        self.assertEqual(intent_router.REPLY, decision.action)

    def test_llm_may_escalate_when_confident(self) -> None:
        decision = intent_router.route(
            "帮我找找漏洞", mode=modes.get_mode("pentest"),
            llm_complete=lambda *a, **k: '{"action":"escalate","target":"http://t.local","reason":"ask"}')
        self.assertTrue(decision.escalates)
        self.assertEqual("http://t.local", decision.target)

    def test_empty_text_replies(self) -> None:
        self.assertEqual(intent_router.REPLY,
                         intent_router.route("   ", mode=modes.get_mode("pentest")).action)


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


class ShippedSkillsTests(unittest.TestCase):
    """The packs on disk are what actually primes each mode's turn."""

    EXPECTED = ("chat", "pentest", "frontend-dev", "backend-dev", "refactor-guard")

    def test_expected_packs_are_present(self) -> None:
        packs = skills.discover()
        for name in self.EXPECTED:
            with self.subTest(pack=name):
                self.assertIn(name, packs)

    def test_every_mode_skill_resolves(self) -> None:
        packs = skills.discover()
        for mode in modes.modes().values():
            with self.subTest(mode=mode.name):
                self.assertIn(mode.skill, packs)

    def test_every_pack_has_a_frontmatter_description(self) -> None:
        for name, pack in skills.discover().items():
            with self.subTest(pack=name):
                head = pack.entry.read_text(encoding="utf-8")[:400]
                self.assertTrue(head.startswith("---"), f"{name} is missing frontmatter")
                self.assertIn("description:", head)

    def test_packs_fit_the_prompt_budget_untruncated(self) -> None:
        marker = "[... skill pack truncated ...]"
        for name in self.EXPECTED:
            with self.subTest(pack=name):
                text = skills.compose_prompt(name)
                self.assertTrue(text.strip(), f"{name} composed to nothing")
                self.assertLessEqual(len(text), skills.DEFAULT_MAX_CHARS)
                self.assertNotIn(marker, text)

    def test_modules_are_lazy(self) -> None:
        base = skills.compose_prompt("pentest")
        self.assertNotIn("A unlocks B", base)
        with_chain = skills.compose_prompt("pentest", modules=("chains",))
        self.assertIn("A unlocks B", with_chain)

    def test_pentest_pack_carries_the_operating_doctrine(self) -> None:
        # SRC_SYSTEM_PROMPT now lives in the pack, not in agents/src_chat.py.
        text = skills.compose_prompt("pentest")
        for phrase in ("授权安全研究员", "SQLi 识别", "IDOR 识别", "不挖 CORS"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, text)

    def test_module_names_are_listed(self) -> None:
        self.assertEqual(
            ["auth", "chains", "evidence", "idor", "injection", "mobile", "recon",
             "ssrf", "url-trust"],
            skills.module_names("pentest"),
        )
        self.assertEqual(["components", "store", "testing", "ui-lib"],
                         skills.module_names("frontend-dev"))

    def test_first_turn_module_floor(self) -> None:
        """第一轮地板:认得出的词带出对应模块,报告纪律永远在,认不出就退回建面。

        真正的深度走 read_knowledge 按需拉,所以这里只挑明显的、并且有上限 ——
        猜宽了就把按需拉取本来要省下的预算又烧回去了。
        """
        self.assertEqual(["evidence", "recon"], skills.select_modules(""))
        self.assertEqual(["evidence", "mobile"], skills.select_modules("这个安卓 App 有导出组件"))
        self.assertEqual(["evidence", "url-trust"], skills.select_modules("帮我看看它的域名校验"))
        # 有上限:一句话里点了一堆词也不会把整包拉进来
        self.assertLessEqual(len(skills.select_modules("安卓 ssrf 注入 越权 域名")),
                             1 + skills.FLOOR_MAX_MATCHED)

    def test_first_turn_floor_never_names_a_module_that_does_not_exist(self) -> None:
        """注入一个不存在的模块名等于给模型指一个不存在的门。"""
        available = set(skills.module_names("pentest"))
        for text in ("", "安卓 ssrf 注入 越权 域名 组合链 侦察 token", "nope"):
            self.assertLessEqual(set(skills.select_modules(text)), available)

    def test_first_turn_floor_is_empty_for_a_pack_without_modules(self) -> None:
        """jobs.py 是对 mode.skill 调的 —— chat 包没有模块,必须是空表而不是报错。"""
        self.assertEqual([], skills.select_modules("随便聊聊", pack="chat"))


if __name__ == "__main__":
    unittest.main()
