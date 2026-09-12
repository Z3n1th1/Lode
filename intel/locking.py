from __future__ import annotations

import os
import threading
import time
from pathlib import Path


class FileLock:
    """Small cross-process lock for atomic JSON/state updates on Windows and POSIX."""

    _locks: dict[Path, threading.RLock] = {}
    _guard = threading.Lock()

    def __init__(self, path: Path, *, timeout_seconds: float = 5.0) -> None:
        self.path = Path(path)
        self.timeout_seconds = max(0.1, float(timeout_seconds))
        self._handle = None
        with self._guard:
            self._thread_lock = self._locks.setdefault(self.path.resolve(), threading.RLock())

    def __enter__(self):  # type: ignore[no-untyped-def]
        self._thread_lock.acquire()
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._handle = self.path.open("a+b")
            if os.name == "nt":
                import msvcrt
                self._handle.seek(0, os.SEEK_END)
                if self._handle.tell() == 0:
                    self._handle.write(b"\0")
                    self._handle.flush()
                self._handle.seek(0)
            deadline = time.monotonic() + self.timeout_seconds
            while True:
                try:
                    if os.name == "nt":
                        import msvcrt
                        self._handle.seek(0)
                        msvcrt.locking(self._handle.fileno(), msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(self._handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError as exc:
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"timed out acquiring intel state lock: {self.path}") from exc
                    time.sleep(0.01)
            return self
        except Exception:
            try:
                self._handle.close()
            except Exception:
                pass
            self._thread_lock.release()
            raise

    def __exit__(self, exc_type, exc, traceback) -> None:  # type: ignore[no-untyped-def]
        try:
            if os.name == "nt":
                import msvcrt
                self._handle.seek(0)
                msvcrt.locking(self._handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
        finally:
            self._handle.close()
            self._thread_lock.release()
