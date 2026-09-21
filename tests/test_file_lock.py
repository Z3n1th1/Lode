"""Tests for core.file_lock — the sidecar byte and the Windows refusal window."""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from typing import Any

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT))

from core.file_lock import AdvisoryFileLock


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


if __name__ == "__main__":
    unittest.main()
