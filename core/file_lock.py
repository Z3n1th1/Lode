"""Small cross-process advisory lock for JSONL state files."""
from __future__ import annotations

import errno
import os
import threading
import time
from pathlib import Path
from typing import Any, BinaryIO, Dict, Optional


_THREAD_LOCKS: Dict[Path, Any] = {}
_THREAD_LOCKS_GUARD = threading.Lock()


def _thread_lock_for(path: Path) -> Any:
    with _THREAD_LOCKS_GUARD:
        return _THREAD_LOCKS.setdefault(path.resolve(), threading.RLock())


class AdvisoryFileLock:
    """Acquire one byte of a sidecar file without deleting the sidecar on exit.

    Closing the descriptor releases the lock after normal exits and process crashes.
    The sidecar is intentionally retained so cleanup never needs a destructive path.
    """

    def __init__(self, path: Path, *, timeout_seconds: float = 5.0, create: bool = True) -> None:
        self.path = Path(path)
        self.timeout_seconds = timeout_seconds
        self.create = create
        self._handle: Optional[BinaryIO] = None
        self._thread_lock = _thread_lock_for(self.path)

    def __enter__(self) -> "AdvisoryFileLock":
        if not self._thread_lock.acquire(timeout=self.timeout_seconds):
            raise TimeoutError(f"timed out acquiring in-process state lock: {self.path}")
        try:
            if self.create:
                self.path.parent.mkdir(parents=True, exist_ok=True)
            handle = self.path.open("a+b" if self.create else "r+b")
            self._handle = handle
            if self.create:
                self._ensure_sidecar_byte(handle)
            else:
                handle.seek(0, os.SEEK_END)
                if handle.tell() == 0:
                    raise OSError(f"state lock sidecar is empty: {self.path}")
            handle.seek(0)
            deadline = time.monotonic() + self.timeout_seconds
            while True:
                try:
                    self._try_lock(handle)
                    return self
                except OSError as exc:
                    if exc.errno not in {errno.EACCES, errno.EAGAIN}:
                        raise
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"timed out acquiring state lock: {self.path}") from exc
                    time.sleep(0.01)
        except Exception:
            if self._handle is not None:
                self._handle.close()
                self._handle = None
            self._thread_lock.release()
            raise

    def _ensure_sidecar_byte(self, handle: BinaryIO, *, attempts: int = 25,
                             delay: float = 0.01) -> None:
        """写进 sidecar 的那一个字节,并容忍"别人刚替我写好"。

        和 :func:`replace_with_retry` 是同一个 Windows 窗口:另一个 handle 正开着这个
        文件时,write/flush 会被拒成 ``PermissionError`` (WinError 5/32)。这个字节不能
        不写 —— ``create=False`` 的读者会把空 sidecar 判成坏文件 —— 所以只能重试;
        重试前重新看一次文件长度,别人已经写好就直接用,不重复写。

        不重试的后果不是"这一次拿不到锁":异常会逃出 ``EventLog.append``,把正在发事件
        的那个线程带走,而它那一批事件**已经丢了**。2026-09-21 实测:
        ``test_concurrent_appends_have_unique_seq`` 4 线程 x 10 条只活下来 30 条。
        """
        for remaining in range(attempts, 0, -1):
            handle.seek(0, os.SEEK_END)
            if handle.tell() != 0:
                return
            try:
                handle.write(b"\0")
                handle.flush()
                return
            except PermissionError:
                if remaining == 1:
                    raise
                time.sleep(delay)

    @staticmethod
    def _try_lock(handle: BinaryIO) -> None:
        if os.name == "nt":
            import msvcrt

            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            return
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    @staticmethod
    def _unlock(handle: BinaryIO) -> None:
        if os.name == "nt":
            import msvcrt

            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            return
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def __exit__(self, exc_type, exc, traceback) -> None:
        handle = self._handle
        self._handle = None
        if handle is None:
            return
        try:
            self._unlock(handle)
        finally:
            handle.close()
            self._thread_lock.release()


def replace_with_retry(staged: Path | str, path: Path | str, *, attempts: int = 25,
                       delay: float = 0.01) -> None:
    """``os.replace``, retried while a concurrent reader holds the destination open.

    On Windows ``os.replace`` raises ``PermissionError`` (WinError 5/32) whenever
    another handle has the target open. Atomic-write helpers write to a staged
    file and then replace, while readers are deliberately lock-free — so that
    window is reachable under load and one ordinary concurrent read can kill the
    write. Retry briefly instead of losing the write.
    """
    staged_path, final_path = Path(staged), Path(path)
    for remaining in range(attempts, 0, -1):
        try:
            os.replace(staged_path, final_path)
            return
        except PermissionError:
            if remaining == 1:
                raise
            time.sleep(delay)

