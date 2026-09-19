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
from console.task_ledger import load_rows, record_run  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
