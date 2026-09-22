"""Tests for core.job_registry — durable, restart-safe job records."""
from __future__ import annotations

import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "core"))

from core import job_registry as jr  # noqa: E402


class JobRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.registry = jr.JobRegistry(Path(self._tmp.name) / "jobs")
        self.addCleanup(self._tmp.cleanup)

    def test_create_and_get_roundtrip(self) -> None:
        record = self.registry.create(session_id="s1", turn_id="T-1", kind="src_loop",
                                      target="https://example.com")
        self.assertTrue(record.job_id.startswith("J-"))
        self.assertEqual(jr.QUEUED, record.status)
        self.assertEqual(os.getpid(), record.owner_pid)
        again = self.registry.get(record.job_id)
        self.assertIsNotNone(again)
        self.assertEqual("s1", again.session_id)
        self.assertEqual("https://example.com", again.target)

    def test_get_missing_returns_none(self) -> None:
        self.assertIsNone(self.registry.get("J-nope"))

    def test_update_sets_finished_at_on_terminal(self) -> None:
        record = self.registry.create(kind="src_loop")
        updated = self.registry.update(record.job_id, status=jr.COMPLETED, summary_ref="sum-1")
        self.assertEqual(jr.COMPLETED, updated.status)
        self.assertGreater(updated.finished_at, 0)
        self.assertEqual("sum-1", updated.summary_ref)

    def test_list_filters_by_session_and_active(self) -> None:
        a = self.registry.create(session_id="s1", kind="src_loop")
        b = self.registry.create(session_id="s2", kind="src_loop")
        self.registry.update(b.job_id, status=jr.COMPLETED)
        self.assertEqual({a.job_id}, {r.job_id for r in self.registry.list(session_id="s1")})
        self.assertEqual({a.job_id}, {r.job_id for r in self.registry.list(active_only=True)})

    def test_stop_flag_is_durable(self) -> None:
        record = self.registry.create(kind="src_loop")
        self.registry.update(record.job_id, status=jr.RUNNING)
        self.registry.request_stop(record.job_id)
        self.assertTrue(self.registry.stop_requested(record.job_id))
        # a fresh registry over the same dir still sees it (survives restart)
        fresh = jr.JobRegistry(self.registry.root)
        self.assertTrue(fresh.stop_requested(record.job_id))
        self.assertEqual(jr.STOP_REQUESTED, fresh.get(record.job_id).status)

    def test_recover_marks_dead_owner_interrupted(self) -> None:
        record = self.registry.create(kind="src_loop")
        self.registry.update(record.job_id, status=jr.RUNNING, owner_pid=999999)
        changed = self.registry.recover(is_alive=lambda pid: False)
        self.assertEqual([record.job_id], [r.job_id for r in changed])
        self.assertEqual(jr.INTERRUPTED, self.registry.get(record.job_id).status)
        self.assertEqual("owner_process_gone", self.registry.get(record.job_id).error)

    def test_recover_requeues_when_auto_resume(self) -> None:
        record = self.registry.create(kind="src_loop")
        self.registry.update(record.job_id, status=jr.RUNNING, owner_pid=999999)
        self.registry.recover(is_alive=lambda pid: False, auto_resume=True)
        self.assertEqual(jr.QUEUED, self.registry.get(record.job_id).status)

    def test_recover_leaves_live_owner_alone(self) -> None:
        record = self.registry.create(kind="src_loop")
        self.registry.update(record.job_id, status=jr.RUNNING, owner_pid=os.getpid())
        self.assertEqual([], self.registry.recover(is_alive=lambda pid: True))
        self.assertEqual(jr.RUNNING, self.registry.get(record.job_id).status)

    def test_recover_honours_a_pre_crash_stop_request(self) -> None:
        record = self.registry.create(kind="src_loop")
        self.registry.update(record.job_id, status=jr.RUNNING, owner_pid=999999)
        self.registry.request_stop(record.job_id)
        changed = self.registry.recover(is_alive=lambda pid: False)
        self.assertEqual([record.job_id], [r.job_id for r in changed])
        self.assertEqual(jr.FAILED, self.registry.get(record.job_id).status)
        self.assertEqual("stopped", self.registry.get(record.job_id).error)

    def test_pid_alive_self_true_and_far_pid_false(self) -> None:
        self.assertTrue(jr.pid_alive(os.getpid()))
        self.assertFalse(jr.pid_alive(0))
        # a very unlikely pid must not raise
        self.assertIn(jr.pid_alive(999_999_999), (True, False))


class RecordReadUnderChurnTests(unittest.TestCase):
    """记录正在被改写的时候,读侧不能把"被拒"说成"不存在"。

    ``_write`` 是 staged + ``os.replace``,读者是故意不加锁的,所以两者之间有一扇
    Windows 才有的窗:``os.replace`` 在飞的时候,读侧 ``open`` 会被拒成
    ``PermissionError`` (WinError 5/32)。以前这个异常被 ``except OSError: return None``
    吞掉,于是"读不到"和"没有这条记录"变成了同一个答案。

    两个后果都在真机上出现过,而且都不需要什么极端条件:

    - ``GET /api/v1/jobs/{id}`` 对一个**一个请求之前刚刚被列出来**的 job 返回 404
      (``tests/test_jobs_api.py::test_turn_creates_a_durable_job_and_completes`` 因此
      偶发 ``KeyError: 'status'``,约 1/5 次全量跑)。
    - ``active_jobs`` 在一条还在跑的会话上报空 —— 那是"一个会话只跑一轮"的闸门
      (``tests/test_chat_api.py::test_second_turn_conflicts_while_running`` 因此偶发
      看到 202 而不是 409)。
    """

    READS = 200

    def test_a_rewritten_record_is_never_reported_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            registry = jr.JobRegistry(Path(tmp) / "jobs")
            record = registry.create(session_id="s1", turn_id="T-1", kind="src_loop")
            stop = threading.Event()
            writes = [0]
            refused = [0]

            def churn() -> None:
                """一直改写这条记录 —— 就是 handler 里 ``ctx.progress()`` 干的事。"""
                n = 0
                while not stop.is_set():
                    n += 1
                    try:
                        registry.update(record.job_id, status=jr.RUNNING,
                                        progress={"phase": "x" * 200, "n": n})
                    except PermissionError:
                        # 写侧的重试预算被读者耗光。不是这条要测的东西,但要如实记下来,
                        # 不然"没有竞争"会被误当成"没有竞态"。
                        refused[0] += 1
                        time.sleep(0.001)
                        continue
                    writes[0] = n

            writer = threading.Thread(target=churn, daemon=True)
            writer.start()
            absent = missed = 0
            try:
                for _ in range(self.READS):
                    if registry.get(record.job_id) is None:
                        absent += 1
                    if not any(r.job_id == record.job_id
                               for r in registry.list(active_only=True)):
                        missed += 1
            finally:
                stop.set()
                writer.join()

            detail = f"writes={writes[0]} refused={refused[0]} reads={self.READS}"
            self.assertEqual((0, 0), (absent, missed),
                             f"absent=get() 报了「没有这条记录」,missed=它从 active 列表里"
                             f"消失了 ({detail})")


if __name__ == "__main__":
    unittest.main()
