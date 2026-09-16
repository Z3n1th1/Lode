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
        # 归一化后的写法(targets.assets 是唯一来源),所以补上了空路径的斜杠
        self.assertEqual("https://target.example.com/", decision.target)
        self.assertEqual(["https://target.example.com/"], decision.targets)

    def test_a_target_list_escalates_with_one_seed_per_asset(self) -> None:
        """一份清单是一批资产:决策带上全部种子,并且按入口/域名/主机分好栏。"""
        decision = intent_router.route(
            "扫描一下 https://a.example.com https://b.example.com c.example.com",
            mode=modes.get_mode("pentest"))
        self.assertTrue(decision.escalates)
        self.assertEqual(
            ["https://a.example.com/", "https://b.example.com/", "https://c.example.com/"],
            decision.targets)
        # 老调用方(飞书那条路)只认 target,它必须是第一个种子
        self.assertEqual(decision.targets[0], decision.target)
        self.assertEqual({"entrypoints": ["https://a.example.com/", "https://b.example.com/"],
                          "domains": [], "hosts": ["c.example.com"]},
                         decision.scope)
        self.assertEqual("targets+action", decision.reason)

    def test_an_embedded_url_glued_to_chinese_is_a_target(self) -> None:
        decision = intent_router.route("对https://rei.com做信息收集", mode=modes.get_mode("pentest"))
        self.assertTrue(decision.escalates)
        self.assertEqual(["https://rei.com/"], decision.targets)

    def test_a_prose_page_full_of_links_does_not_escalate(self) -> None:
        """粘一整页说明进来时,里面散落的链接不该变成一串自动开跑的猎场。

        目标是识别到了 —— 但它们不是这句话的主体(说明文字才是),所以只回报,
        不发请求。确认单/对话是让操作员自己挑的地方。
        """
        prose = ("扫描一下 "
                 "https://a.example.com https://b.example.com https://c.example.com "
                 "https://d.example.com https://e.example.com https://docs.example.org "
                 "这段说明我整段粘进来了 你读懂它再回答 "
                 "不要对着里面提到的每个域名都跑一遍 那样等于对一堆越权目标发请求 "
                 "我们应该谨慎一点 先看清楚授权范围 再决定要不要开跑")
        decision = intent_router.route(prose, mode=modes.get_mode("pentest"))
        self.assertEqual(intent_router.REPLY, decision.action)
        self.assertEqual("targets_not_a_list", decision.reason)
        self.assertEqual([], decision.targets)

    def test_a_terse_verb_is_enough(self) -> None:
        """操作员打一个"扫"字就该认 —— 动作词是按词根匹配的,不是整词表。"""
        decision = intent_router.route("扫 x.example.com、y.example.com",
                                       mode=modes.get_mode("pentest"))
        self.assertTrue(decision.escalates)
        self.assertEqual(["https://x.example.com/", "https://y.example.com/"], decision.targets)

    def test_the_classifier_is_asked_when_no_rule_matched(self) -> None:
        """目标在、但没有一个认识的动词 -> 兜底分类器说了算(而不是永远"只回话")。"""
        asked: list = []

        def fake_complete(system, user, **kwargs):
            asked.append(user)
            return '{"action":"escalate","subtask_kind":"src_loop","reason":"ask"}'

        decision = intent_router.route("x.example.com 和 y.example.com 这两个",
                                       mode=modes.get_mode("pentest"), llm_complete=fake_complete)
        self.assertEqual(1, len(asked))
        self.assertTrue(decision.escalates)
        # 分类器只回答要不要开跑:目标以解析结果为准,所以两个都开
        self.assertEqual(["https://x.example.com/", "https://y.example.com/"], decision.targets)
        self.assertEqual("ask", decision.reason)

    def test_the_classifier_cannot_widen_a_prose_page(self) -> None:
        """说明文字里散落的链接不因为分类器点头就变成一串猎场 —— 这条先判,不花钱。"""
        asked: list = []

        def fake_complete(system, user, **kwargs):
            asked.append(user)
            return '{"action":"escalate","reason":"sure"}'

        prose = ("https://a.example.com\nhttps://b.example.com\nhttps://c.example.com\n"
                 "https://d.example.com\nhttps://e.example.com\nhttps://docs.example.org\n"
                 "这是那份说明的正文,我整段粘进来了\n"
                 "你要先读懂它在讲什么\n"
                 "而不是对着里面提到的每个域名都跑一遍\n"
                 "那样等于对一堆越权目标发请求\n"
                 "谨慎一点\n"
                 "先看清楚授权范围\n"
                 "再决定要不要开跑\n"
                 "谢谢")
        decision = intent_router.route(prose, mode=modes.get_mode("pentest"),
                                       llm_complete=fake_complete)
        self.assertEqual([], asked)          # 没花钱:主体判定在分类器之前
        self.assertEqual(intent_router.REPLY, decision.action)
        self.assertEqual("targets_not_a_list", decision.reason)

    def test_the_classifiers_own_target_is_ignored_when_we_parsed_the_text(self) -> None:
        """模型嘴里的目标没有过闸门,也没有归一化,不能拿它当任务目标。"""
        decision = intent_router.route(
            "x.example.com 这个怎么样", mode=modes.get_mode("pentest"),
            llm_complete=lambda *a, **k: '{"action":"escalate","target":"http://evil.example.net/","reason":"ask"}')
        self.assertTrue(decision.escalates)
        self.assertEqual(["https://x.example.com/"], decision.targets)

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
