"""Tests for core.file_lock — the sidecar byte and the Windows refusal window."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT))

from core.file_lock import AdvisoryFileLock, read_text_with_retry


class _StubHandle:
    """只实现 ``_ensure_sidecar_byte`` 用到的四件事,好让"被拒"可复现。"""

    def __init__(self, initial: bytes = b"", refuse_first: int = 0) -> None:
        self.buf = initial
        self.pos = 0
        self.refuse_first = refuse_first
        self.writes = 0

    def seek(self, offset: int, whence: int = 0) -> int:
        self.pos = len(self.buf) if whence == os.SEEK_END else offset
        return self.pos

    def tell(self) -> int:
        return self.pos

    def write(self, data: bytes) -> int:
        self.writes += 1
        if self.writes <= self.refuse_first:
            # Windows 上另一个 handle 正开着这个文件时就是这个形状(WinError 5/32)。
            raise PermissionError(13, "Permission denied")
        self.buf += data
        self.pos = len(self.buf)
        return len(data)

    def flush(self) -> None:
        return None


def _lock() -> AdvisoryFileLock:
    return AdvisoryFileLock(Path("unused-sidecar"))


class SidecarByteTests(unittest.TestCase):
    """写 sidecar 首字节不能被拒一次就放弃。

    放弃的后果不是"这次没拿到锁":``PermissionError`` 会逃出 ``EventLog.append``,把正在
    发事件的线程带走,而它那一批事件**已经丢了**。2026-09-21 实测:
    ``test_concurrent_appends_have_unique_seq`` 4 线程 × 10 条只活下来 30 条。
    """

    def test_a_refused_write_is_retried_until_it_lands(self):
        handle: Any = _StubHandle(refuse_first=2)
        _lock()._ensure_sidecar_byte(handle, delay=0.0)
        self.assertEqual(b"\0", handle.buf)
        self.assertEqual(3, handle.writes, "被拒两次之后第三次应当成功,而不是放弃")

    def test_the_error_is_not_swallowed_when_every_attempt_is_refused(self):
        """重试到底还是不行时,要抛出来 —— 静默继续等于后面的写入凭空失败。"""
        handle: Any = _StubHandle(refuse_first=10_000)
        with self.assertRaises(PermissionError):
            _lock()._ensure_sidecar_byte(handle, attempts=3, delay=0.0)
        self.assertEqual(3, handle.writes)

    def test_a_byte_someone_else_already_wrote_is_reused(self):
        """别的进程刚写好这一个字节,就不该重复写 —— 重试前要重新看一次长度。"""
        handle: Any = _StubHandle(initial=b"\0")
        _lock()._ensure_sidecar_byte(handle, delay=0.0)
        self.assertEqual(0, handle.writes)
        self.assertEqual(b"\0", handle.buf)


class ReadRetryTests(unittest.TestCase):
    """被拒一次就当成"这个文件不存在",是这扇窗里最贵的错法。

    ``_write`` 用 staged + ``os.replace`` 换文件,而读侧是故意不加锁的 —— 读者会落进那
    个窗口,Windows 上表现为 ``PermissionError`` (WinError 5/32)。实测(2026-09-22,
    一条被持续改写的 job 记录):``GET /api/v1/jobs/{id}`` 对一个请求前刚刚被列出来的
    job 返回 404,``active_jobs`` 在一条还在跑的会话上报空 —— 而后者正是"一个会话只跑
    一轮"的闸门。

    这和 ``SidecarByteTests`` 是同一条规则的两面:写侧的重试已经在了,读侧的没有。
    """

    def test_a_refused_open_is_retried_until_it_lands(self):
        attempts: list = []
        real = Path.read_text

        def flaky(self, **kwargs):
            attempts.append(self)
            if len(attempts) <= 2:
                raise PermissionError(13, "Permission denied")
            return real(self, **kwargs)

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "record.json"
            target.write_text('{"status": "running"}', encoding="utf-8")
            with patch.object(Path, "read_text", flaky):
                text = read_text_with_retry(target, delay=0.0)

        self.assertEqual('{"status": "running"}', text)
        self.assertEqual(3, len(attempts), "被拒两次之后第三次应当成功,而不是报不存在")

    def test_the_error_is_not_swallowed_when_every_attempt_is_refused(self):
        """重试到底还是不行就要抛出来 —— 返回空内容等于把"读不到"说成"没有"。"""
        with patch.object(Path, "read_text", side_effect=PermissionError(13, "denied")) as stub:
            with self.assertRaises(PermissionError):
                read_text_with_retry("unused.json", attempts=3, delay=0.0)
        self.assertEqual(3, stub.call_count)

    def test_a_missing_file_is_not_retried(self):
        """真的不存在是普通的 404 路径,不该为它在重试预算里等满 250ms。"""
        with patch.object(Path, "read_text", side_effect=FileNotFoundError(2, "no such file")) as stub:
            with self.assertRaises(FileNotFoundError):
                read_text_with_retry("unused.json", delay=0.0)
        self.assertEqual(1, stub.call_count, "文件不存在不该被重试 —— 那是普通的「没这条记录」")


if __name__ == "__main__":
    unittest.main()
