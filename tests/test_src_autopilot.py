from __future__ import annotations

import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from agents.src_autopilot import SrcAutopilot
from agents.surface_discovery import SurfaceScope
from core.src_blackboard import SrcBlackboard


class SrcAutopilotTests(unittest.TestCase):
    def _scope(self) -> SurfaceScope:
        return SurfaceScope(
            "fixture-src",
            "written authorization fixture",
            allowed_domains=("example.com",),
            delay_seconds=0.1,
        )

    def _result(self) -> dict:
        return {
            "schema": "SrcSurfaceResult/v1",
            "target": "https://example.com/",
            "base_url": "https://example.com",
            "paths": [
                "/api/v1/users?token=secret-value",
                "/admin/export?customer_id=123",
                "/health",
            ],
            "api_urls": ["https://api.example.com/graphql?sig=private-signature"],
            "sources": {
                "/api/v1/users?token=secret-value": ["openapi"],
                "/admin/export?customer_id=123": ["js"],
            },
            "requests": [
                {"url": "https://example.com/", "status": 200},
                {"url": "https://example.com/robots.txt", "status": 404},
            ],
            "errors": ["blocked:https://example.com/logout:state_changing_url"],
        }

    def test_the_crawler_is_audited_too(self) -> None:
        """爬虫的请求要进和 agent 同一份 http-actions.jsonl。

        在 auto 那条路上 cmd_scan 会写 surface-*.json、auto 不写,于是爬虫花掉的额度
        (真机实测一轮 60 里占 21 个)在任何文件里都找不到 —— 而红线 10 要的是"测试全程留痕"。
        """
        from agents.src_agent import HTTP_ACTION_LOG

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bb_path = root / "src-blackboard.json"
            agent = SrcAutopilot(self._scope(), root / "state.json", root,
                                 max_rounds=1, blackboard_path=bb_path,
                                 discover_fn=lambda *a, **kw: self._result())
            agent.run_round(["https://example.com/"])

            path = bb_path.parent / HTTP_ACTION_LOG
            self.assertTrue(path.is_file(), "爬虫的请求没有落审计")
            rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
                    if line.strip()]
            self.assertTrue(rows)
            self.assertTrue(all(row["kind"] == "crawl" for row in rows))
            self.assertTrue(all(row["method"] == "GET" for row in rows))
            decisions = [row["decision"] for row in rows]
            self.assertEqual(2, decisions.count("allowed"), decisions)
            # 被挡下来的那次也要留痕,不然"它想过什么"没有记录。
            self.assertIn("refused:state_changing_url", decisions)

    def test_first_round_builds_prioritized_deduplicated_queue_without_persisting_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            agent = SrcAutopilot(self._scope(), root / "state.json", root / "out", max_rounds=3)
            summary = agent.run_round(["https://example.com"], results=[self._result()])
            candidates = json.loads((root / "out" / "src-autopilot-candidates.json").read_text(encoding="utf-8"))["candidates"]

        self.assertEqual("awaiting_next_round", summary["status"])
        self.assertEqual(4, summary["candidate_count"])
        self.assertGreaterEqual(candidates[0]["priority"], candidates[-1]["priority"])
        serialized = json.dumps(candidates, ensure_ascii=False)
        self.assertNotIn("secret-value", serialized)
        self.assertNotIn("private-signature", serialized)
        self.assertIn("token=[redacted]", serialized)
        self.assertTrue(all(item["requires_human_review"] for item in candidates))

    def test_the_executable_url_outlives_the_redaction(self) -> None:
        """展示形式每个参数值都是 [redacted]/[value] —— 拿它去请求必然是 404。

        这就是"候选活着"的全部意义:一个 id 是好的探针,`[value]` 不是。

        | 原文 | 展示(落盘/给模型) | 执行 |
        |---|---|---|
        | `?token=secret-value` | `?token=[redacted]` | 无查询串 |
        | `?customer_id=123` | `?customer_id=[value]` | `?customer_id=123` |
        | `?sig=private-signature` | `?sig=[redacted]` | 无查询串 |
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            agent = SrcAutopilot(self._scope(), root / "state.json", root / "out", max_rounds=3)
            agent.run_round(["https://example.com"], results=[self._result()])
            candidates = json.loads(
                (root / "out" / "src-autopilot-candidates.json").read_text(encoding="utf-8"))["candidates"]
            board = SrcBlackboard(root / "src-blackboard.json").snapshot()

        by_url = {item["url"]: item for item in candidates}
        self.assertEqual("https://example.com/api/v1/users",
                         by_url["https://example.com/api/v1/users?token=[redacted]"]["probe_url"])
        self.assertEqual("https://example.com/admin/export?customer_id=123",
                         by_url["https://example.com/admin/export?customer_id=[value]"]["probe_url"])
        self.assertEqual("https://api.example.com/graphql",
                         by_url["https://api.example.com/graphql?sig=[redacted]"]["probe_url"])

        # 凭据值一个都没落盘 —— 修的是"能不能请求",不是"少打点码"。
        serialized = json.dumps(candidates, ensure_ascii=False)
        self.assertNotIn("secret-value", serialized)
        self.assertNotIn("private-signature", serialized)

        # 黑板同时是执行的唯一真相源,所以两份都要在:intent.target 给人看,
        # intent.probe_url 拿去请求。
        intents = {item["target"]: item for item in board["intents"]}
        intent = intents["https://example.com/admin/export?customer_id=[redacted]"]
        self.assertEqual("https://example.com/admin/export?customer_id=123", intent["probe_url"])
        probes = json.dumps([item.get("probe_url") for item in board["intents"]], ensure_ascii=False)
        self.assertNotIn("[value]", probes)
        self.assertNotIn("[redacted]", probes)
        self.assertNotIn("secret-value", probes)

    def test_duplicate_round_converges_and_restart_does_not_repeat_network_work(self) -> None:
        calls = []

        def discover(scope, target, *, max_scripts, budget=None):
            calls.append((target, max_scripts))
            return self._result()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            agent = SrcAutopilot(
                self._scope(), root / "state.json", root / "out", max_rounds=4,
                discover_fn=discover,
            )
            first = agent.run_round(["https://example.com"])
            second = agent.run_round(results=[self._result()])
            restarted = SrcAutopilot(
                self._scope(), root / "state.json", root / "out", max_rounds=4,
                discover_fn=lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("network replay")),
            )
            third = restarted.run_round(results=[self._result()])
            fourth = restarted.run_round(results=[self._result()])

        self.assertEqual(1, len(calls))
        self.assertEqual("awaiting_next_round", first["status"])
        self.assertEqual("awaiting_next_round", second["status"])
        self.assertEqual("stopped", third["status"])
        self.assertEqual("converged_no_new_candidates", third["stop_reason"])
        self.assertEqual("already_terminal", fourth["event"])

    def test_out_of_scope_result_is_blocked_without_adding_candidates(self) -> None:
        result = self._result()
        result["base_url"] = "https://outside.example.net"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            agent = SrcAutopilot(self._scope(), root / "state.json", root / "out")
            summary = agent.run_round(["https://example.com"], results=[result])
            state = json.loads((root / "state.json").read_text(encoding="utf-8"))

        self.assertEqual(0, summary["candidate_count"])
        self.assertEqual(1, state["rounds"][0]["blocked_candidates"])

    def test_missing_authorization_and_unbounded_limits_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "surface_authorization_required"):
            SrcAutopilot(
                SurfaceScope("fixture", "", allowed_domains=("example.com",)),
                Path(tempfile.gettempdir()) / "src-auto-state.json",
                Path(tempfile.gettempdir()) / "src-auto-out",
            )
        with self.assertRaisesRegex(ValueError, "max_rounds"):
            SrcAutopilot(self._scope(), Path("state.json"), Path("out"), max_rounds=99)

    def test_blackboard_mirror_and_concurrent_rounds_keep_state_consistent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            agent = SrcAutopilot(self._scope(), root / "state.json", root / "out", max_rounds=4)
            with ThreadPoolExecutor(max_workers=2) as pool:
                summaries = list(pool.map(lambda _: agent.run_round(["https://example.com"], results=[self._result()]), [1, 2]))
            state = json.loads((root / "state.json").read_text(encoding="utf-8"))
            board = SrcBlackboard(root / "src-blackboard.json").snapshot()

        self.assertEqual({1, 2}, {item["round"] for item in state["rounds"]})
        self.assertEqual(2, state["current_round"])
        self.assertEqual(4, len(board["intents"]))
        self.assertEqual(4, len(board["facts"]))
        self.assertEqual(2, len(summaries))

    def test_single_round_run_accepts_default_convergence_window(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            agent = SrcAutopilot(self._scope(), root / "state.json", root / "out", max_rounds=1)
            summary = agent.run_round(["https://example.com"], results=[self._result()])
        self.assertEqual("stopped", summary["status"])
        self.assertEqual("max_rounds", summary["stop_reason"])


class TemplateFoldingTests(unittest.TestCase):
    """可枚举的资源不该一个 id 一个候选。

    没有折叠时,一个 /users/{id} 面就有 200 个候选:max_candidates(100)被它一个
    吃满,reasoner 的 50 条窗口也全是它,真正有意思的端点根本进不了模型视野。
    """

    def _scope(self) -> SurfaceScope:
        return SurfaceScope("fixture-src", "written authorization fixture",
                            allowed_domains=("example.com",), delay_seconds=0.1)

    def _run(self, paths, *, rounds=1):
        result = {
            "schema": "SrcSurfaceResult/v1", "target": "https://example.com/",
            "base_url": "https://example.com", "paths": paths, "api_urls": [],
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            agent = SrcAutopilot(self._scope(), root / "state.json", root / "out", max_rounds=rounds)
            summaries = [agent.run_round(["https://example.com"], results=[result])
                         if index == 0 else agent.run_round(results=[result])
                         for index in range(rounds)]
            candidates = json.loads(
                (root / "out" / "src-autopilot-candidates.json").read_text(encoding="utf-8"))["candidates"]
            state = json.loads((root / "state.json").read_text(encoding="utf-8"))
        return summaries, candidates, state

    def test_enumerated_ids_fold_into_one_candidate(self) -> None:
        summaries, candidates, _ = self._run([f"/api/v1/users/{n}" for n in range(1, 6)])
        self.assertEqual(1, summaries[0]["candidate_count"])
        self.assertEqual(1, len(candidates))
        self.assertEqual(5, candidates[0]["variants"])
        self.assertEqual("https://example.com/api/v1/users/1", candidates[0]["url"])
        self.assertEqual(5, len(candidates[0]["variant_samples"]))
        # 家族身份是形状,不是实例 —— candidate_id 仍然钉在具体 url 上。
        self.assertNotEqual("", candidates[0]["template_id"])

    def test_a_digit_inside_a_segment_is_not_an_id(self) -> None:
        """"整段判定"是这条的全部意义:endpoint0/endpoint1/e2 是三条路径。

        按"含数字"归类会把它们并成一个家族,而它们之间没有任何关系。
        """
        _, candidates, _ = self._run(["/api/endpoint0", "/api/endpoint1", "/api/e2"])
        self.assertEqual(3, len(candidates))

    def test_uuid_and_hex_segments_are_their_own_shapes(self) -> None:
        _, candidates, _ = self._run([
            "/orders/1a2b3c4d-1111-2222-3333-444455556666",
            "/orders/2b3c4d5e-2222-3333-4444-555566667777",
            "/blobs/9f8e7d6c5b4a3210",
            "/blobs/1a2b3c4d5e6f7081",
        ])
        self.assertEqual(2, len(candidates))
        variants = sorted(item["variants"] for item in candidates)
        self.assertEqual([2, 2], variants)

    def test_the_same_shape_on_two_hosts_stays_two_candidates(self) -> None:
        """合并键是 (template_id, host):同一个形状在两台主机上是两件事。"""
        _, candidates, _ = self._run(["https://a.example.com/users/1", "https://b.example.com/users/2"])
        self.assertEqual(2, len(candidates))

    def test_re_seeing_the_same_instance_does_not_inflate_variants(self) -> None:
        """同一份 surface 结果每一轮都会被再喂一遍,计数不能跟着轮数涨。"""
        _, candidates, state = self._run([f"/api/v1/users/{n}" for n in range(1, 4)], rounds=2)
        self.assertEqual([1, 0], [row["new_candidates"] for row in state["rounds"]])
        self.assertEqual(3, candidates[0]["variants"])

    def test_variant_samples_saturate_instead_of_growing_without_bound(self) -> None:
        """枚举面可以是几千个 id;记录在 MAX_VARIANT_SAMPLES 处封顶,不假装精确。"""
        from agents.src_autopilot import MAX_VARIANT_SAMPLES

        _, candidates, _ = self._run([f"/api/v1/users/{n}" for n in range(1, 200)])
        self.assertEqual(1, len(candidates))
        self.assertEqual(MAX_VARIANT_SAMPLES, candidates[0]["variants"])


if __name__ == "__main__":
    unittest.main()
