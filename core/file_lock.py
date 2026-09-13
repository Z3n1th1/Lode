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
            if self.create and handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
            elif not self.create:
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

