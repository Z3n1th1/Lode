"""Tests for console.task_ledger — the bridge from a CLI run to the Console UI.

The console only ever shows what it can read out of ``strix_tasks.jsonl``, so the
point of these is not "a line was appended" but "the projection turns that line
into a visible project" — the failure this bridge exists to fix was rows that
parse fine and still never appear.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "core"))

from console.projections import ReadOnlyControlPlane  # noqa: E402
from console.task_ledger import begin_run, finish_run, load_rows, record_run  # noqa: E402


class TaskLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.state = Path(self._tmp.name) / "state"
        self.out = Path(self._tmp.name) / "out" / "api.example.com"
        self.out.mkdir(parents=True)
        self.addCleanup(self._tmp.cleanup)

    def test_a_recorded_run_shows_up_as_a_project(self) -> None:
        """光写进去不算数 —— 投影得把它变成一个项目,界面上才有东西。"""
        record_run(self.state, target="https://api.example.com/", output_path=self.out)

        rows = load_rows(self.state)
        self.assertEqual(1, len(rows))
        page = ReadOnlyControlPlane(self.state).projects()
        # project_id 是 target 派生的 slug(scheme 也在里面),别看它长得像主机名
        self.assertEqual(["https-api.example.com"], [p["project_id"] for p in page["projects"]])
        self.assertEqual("https://api.example.com/", page["projects"][0]["target"])
        self.assertEqual(1, page["projects"][0]["task_count"])
        self.assertEqual(1, page["total"])

    def test_the_row_uses_the_ledgers_own_vocabulary(self) -> None:
        """台账认 ``finished``,不认 job 那边的 ``completed``。

        写错状态不会报错 —— 投影保留默认值,界面上就是"从没开始过"。这条钉住它。
        """
        row = record_run(self.state, target="https://a.example.com/", output_path=self.out)
        from console.deps import ALLOWED_TASK_STATUSES, TASK_ID_RE

        self.assertTrue(TASK_ID_RE.fullmatch(row["id"]), row["id"])
        self.assertIn(row["status"], ALLOWED_TASK_STATUSES)

    def test_an_unknown_status_does_not_become_a_silent_no_show(self) -> None:
        record_run(self.state, target="https://b.example.com/", output_path=self.out,
                   status="completed")  # the job-runner word, not the ledger's
        self.assertEqual("finished", load_rows(self.state)[0]["status"])

    def test_task_ids_do_not_collide_within_the_same_millisecond(self) -> None:
        ids = {record_run(self.state, target=f"https://h{i}.example.com/", output_path=self.out)["id"]
               for i in range(5)}
        self.assertEqual(5, len(ids))
        self.assertEqual(5, len(load_rows(self.state)))

    def test_no_profile_is_left_empty_rather_than_invented(self) -> None:
        """投影侧 require_profile=False 会显示 "—"。填个假的会让人以为走过 profile 那条链。"""
        row = record_run(self.state, target="https://c.example.com/", output_path=self.out)
        self.assertEqual("", row["profile_name"])
        self.assertEqual("", row["goal_id"])

    def test_a_truncated_tail_is_skipped_not_fatal(self) -> None:
        record_run(self.state, target="https://d.example.com/", output_path=self.out)
        ledger = self.state / "strix_tasks.jsonl"
        with ledger.open("a", encoding="utf-8") as handle:
            handle.write('{"id": "T-1", "target": "https://half')  # 进程被杀留下的半行
        self.assertEqual(1, len(load_rows(self.state)))

    def test_it_does_not_fake_findings_or_a_report(self) -> None:
        """建面的产出是面,不是漏洞也不是渗透报告 —— 写假的等于在可信屏上放不实发现。"""
        record_run(self.state, target="https://e.example.com/", output_path=self.out)
        self.assertEqual([], list(self.out.rglob("findings.sarif")))
        self.assertEqual([], list(self.out.rglob("standard_report_cn.md")))
        self.assertEqual([], ReadOnlyControlPlane(self.state).findings())

    def test_records_from_two_runs_fold_into_one_project(self) -> None:
        for out in (self.out, Path(self._tmp.name) / "out2" / "api.example.com"):
            out.mkdir(parents=True, exist_ok=True)
            record_run(self.state, target="https://api.example.com/", output_path=out)
        page = ReadOnlyControlPlane(self.state).projects()
        self.assertEqual(1, len(page["projects"]))
        self.assertEqual(2, page["projects"][0]["task_count"])

    def test_the_list_pages_and_reports_the_real_total(self) -> None:
        """静默截断会让人以为"就这么多"。分页必须把总数带出去。"""
        for i in range(25):
            record_run(self.state, target=f"https://h{i:02d}.example.com/", output_path=self.out)

        page = ReadOnlyControlPlane(self.state).projects(offset=0, limit=10)
        self.assertEqual(25, page["total"])
        self.assertEqual(10, len(page["projects"]))
        rest = ReadOnlyControlPlane(self.state).projects(offset=20, limit=10)
        self.assertEqual(5, len(rest["projects"]))          # 尾页
        self.assertEqual(20, rest["offset"])
        # 全部页拼起来不重不漏
        every = [p["project_id"] for o in (0, 10, 20)
                 for p in ReadOnlyControlPlane(self.state).projects(offset=o, limit=10)["projects"]]
        self.assertEqual(25, len(set(every)))

    def test_an_absurd_limit_is_clamped_not_honoured(self) -> None:
        from console.deps import MAX_PROJECT_PAGE

        page = ReadOnlyControlPlane(self.state).projects(limit=10 ** 9)
        self.assertEqual(MAX_PROJECT_PAGE, page["limit"])
        self.assertLessEqual(0, page["offset"])

    def test_the_lock_sidecar_is_created_so_locked_readers_work(self) -> None:
        """``_read_events`` 要求 .lock 在场,否则那些视图一律 unavailable。"""
        record_run(self.state, target="https://f.example.com/", output_path=self.out)
        lock = self.state / "strix_tasks.jsonl.lock"
        self.assertTrue(lock.is_file())
        payload = json.loads((self.state / "strix_tasks.jsonl").read_text(encoding="utf-8").strip())
        self.assertTrue(payload["output_path"])


class InFlightRunTests(unittest.TestCase):
    """``begin_run``/``finish_run`` —— 让"正在扫的那台"在界面上真的存在。

    ``record_run`` 只写一行,而且写完就是 ``finished``;一台正在扫的主机在 Console
    上从来不存在。这组钉住三件事:开工时台账里**先**出现 ``running``;收尾之后它折叠
    回**同一个** task(不是一个项目里冒出两条记录);以及 0 和"没记"是两码事。
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.state = Path(self._tmp.name) / "state"
        self.out = Path(self._tmp.name) / "out" / "login.example.com"
        self.out.mkdir(parents=True)
        self.addCleanup(self._tmp.cleanup)

    def _card(self):
        page = ReadOnlyControlPlane(self.state).projects()
        return next(p for p in page["projects"] if p["project_id"] == "https-login.example.com"), page

    def test_an_open_run_is_visible_while_it_works(self) -> None:
        begin_run(self.state, target="https://login.example.com/", output_path=self.out,
                  batch_index=137, batch_size=325)

        card, page = self._card()
        self.assertEqual("running", card["status"])
        self.assertEqual("137/325", f"{card['batch_index']}/{card['batch_size']}")
        self.assertTrue(card["running_task_id"])
        # 横幅读的是全局那一条,所以它跟当前页无关(翻到第 9 页也该看得见)
        self.assertEqual("https://login.example.com/", page["running"]["target"])
        self.assertEqual((137, 325),
                         (page["running"]["batch_index"], page["running"]["batch_size"]))

    def test_finishing_folds_back_into_one_task(self) -> None:
        opened = begin_run(self.state, target="https://login.example.com/", output_path=self.out)
        finish_run(self.state, task_id=opened["id"], target="https://login.example.com/",
                   output_path=self.out,
                   surface={"paths": 12, "api_urls": 3, "scripts": 8, "status": 200})

        # 两行台账,仍然一个项目、一个 task —— 折叠靠 id,不是靠"再来一条记录"
        self.assertEqual(2, len(load_rows(self.state)))
        card, page = self._card()
        self.assertEqual(1, card["task_count"])
        self.assertEqual("done", card["status"])
        self.assertEqual("", card["running_task_id"])
        self.assertIsNone(page["running"])
        self.assertEqual((12, 3, 8, 200),
                         (card["surface_paths"], card["surface_api"],
                          card["surface_scripts"], card["http_status"]))
        self.assertTrue(card["has_surface"])
        # 收尾行刻意不带 created_ts,所以 最近活动 停在**开工**那一刻而不是收尾那一刻
        self.assertEqual(load_rows(self.state)[0]["created_ts"], card["last_activity"])

    def test_a_zero_surface_is_a_real_answer_not_a_missing_one(self) -> None:
        """扫到了、但这台什么都没有(0/0/0 + 403)和"这条路不产生面计数"长得像,语义不同。"""
        opened = begin_run(self.state, target="https://login.example.com/", output_path=self.out)
        finish_run(self.state, task_id=opened["id"], target="https://login.example.com/",
                   output_path=self.out,
                   surface={"paths": 0, "api_urls": 0, "scripts": 0, "status": 403})

        card, _ = self._card()
        self.assertTrue(card["has_surface"])
        self.assertEqual(403, card["http_status"])
        self.assertEqual(0, card["surface_paths"])

    def test_a_run_without_surface_counts_does_not_claim_zero(self) -> None:
        """``auto`` 产出候选、不爬面 —— 那要说"没有面计数",不是"面是 0"。"""
        opened = begin_run(self.state, target="https://login.example.com/", output_path=self.out)
        finish_run(self.state, task_id=opened["id"], target="https://login.example.com/",
                   output_path=self.out)

        card, _ = self._card()
        self.assertFalse(card["has_surface"])

    def test_a_failed_run_does_not_stay_running(self) -> None:
        opened = begin_run(self.state, target="https://login.example.com/", output_path=self.out)
        finish_run(self.state, task_id=opened["id"], status="failed",
                   target="https://login.example.com/", error="ValueError: bad target")

        card, page = self._card()
        self.assertIsNone(page["running"])
        self.assertEqual("", card["running_task_id"])
        self.assertFalse(card["has_surface"])
        # 项目行的状态只有 running/done 两档(既有口径),所以失败在**详情**里看:
        # task 自己记着 failed。注意这意味着列表上"失败"和"跑完了什么都没出"目前
        # 长得一样 —— 要分开得先扩状态词表,那是另一件事。
        detail = ReadOnlyControlPlane(self.state).project_detail("https-login.example.com")
        statuses = [t["status"] for s in detail["sessions"] for t in s["tasks"]]
        self.assertEqual(["failed"], statuses)

    def test_rescanning_a_target_clears_the_orphan(self) -> None:
        """被 SIGKILL 留下的 running 行没人来收尾 —— 重扫时就地补成 interrupted。

        没有这一步,界面上会永远挂着一行假的"在跑",而它对应的进程早就不在了。
        """
        orphan = begin_run(self.state, target="https://login.example.com/", output_path=self.out)
        rescanned = begin_run(self.state, target="https://login.example.com/", output_path=self.out)

        rows = {row["id"]: row for row in load_rows(self.state)}
        self.assertEqual("interrupted", rows[orphan["id"]]["status"])
        self.assertEqual("running", rows[rescanned["id"]]["status"])
        card, page = self._card()
        self.assertEqual("running", card["status"])
        # 两次开工是两个 task(和 record_run 跑两趟同一个结果),但只有新的那条在跑
        self.assertEqual(2, card["task_count"])
        self.assertEqual(rescanned["id"], page["running"]["task_id"])

    def test_a_run_identity_makes_the_session_real(self) -> None:
        """``auto`` 结束时把 autopilot 真实的 run id 写进 goal_id,会话列才不是 0。"""
        opened = begin_run(self.state, target="https://login.example.com/", output_path=self.out)
        finish_run(self.state, task_id=opened["id"], target="https://login.example.com/",
                   output_path=self.out, goal_id="SA-abc123")

        card, _ = self._card()
        self.assertEqual(1, card["session_count"])
        detail = ReadOnlyControlPlane(self.state).project_detail("https-login.example.com")
        self.assertEqual(["SA-abc123"], [s["session_id"] for s in detail["sessions"]])

    def test_a_legacy_row_reports_no_surface_rather_than_zero(self) -> None:
        """老路径(cmd_surface_import / record_run)写的行没有面计数,界面要画 "—"。"""
        record_run(self.state, target="https://login.example.com/", output_path=self.out)

        card, _ = self._card()
        self.assertEqual("done", card["status"])
        self.assertFalse(card["has_surface"])

    def test_the_card_does_not_carry_paths_or_error_text(self) -> None:
        """新加的数值字段不该顺手把 output_path / error 带上屏。

        台账是本机的,项目卡片是会上屏的 —— 这两者之间的边界以前靠"投影只挑它要的
        字段"来维持。加了新字段就得把这条重新钉一遍,否则下次多加一个字段就可能
        把一个本机路径(或一段含密钥的异常文本)漏到界面上。
        """
        opened = begin_run(self.state, target="https://login.example.com/", output_path=self.out)
        finish_run(self.state, task_id=opened["id"], status="failed",
                   target="https://login.example.com/", output_path=self.out,
                   error="ValueError: token=hunter2 at /etc/shadow")

        serialized = json.dumps(ReadOnlyControlPlane(self.state).projects(), ensure_ascii=False)
        self.assertNotIn("output_path", serialized)
        self.assertNotIn("hunter2", serialized)
        self.assertNotIn("/etc/shadow", serialized)
        self.assertNotIn("error", serialized)


if __name__ == "__main__":
    unittest.main()
