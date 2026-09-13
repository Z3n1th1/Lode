"""Durable, restart-safe job registry (one JSON file per job).

Replaces the process-local ``_src_agent_state`` dict + daemon thread the Console
used for background SRC runs: those were lost on restart and could not be
stopped. Records live on disk, are written atomically, and a start-up
:meth:`JobRegistry.recover` marks jobs whose owner process died as
``interrupted`` (optionally re-queueing them).

Plain files + :class:`~core.file_lock.AdvisoryFileLock` (``msvcrt`` on Windows)
are deliberate: this is a single-user, loopback-only app, so a broker/DB would
add a daemon and a failure mode for no benefit.
"""
from __future__ import annotations

import json
import os
import secrets
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

try:
    from core.file_lock import AdvisoryFileLock
except ImportError:  # pragma: no cover
    from file_lock import AdvisoryFileLock  # type: ignore

SCHEMA = "LodeJob/v1"
JOB_ID_RE = r"^J-[A-Za-z0-9_.-]{1,80}$"

QUEUED = "queued"
RUNNING = "running"
WAITING_APPROVAL = "waiting_approval"
STOP_REQUESTED = "stop_requested"
COMPLETED = "completed"
FAILED = "failed"
INTERRUPTED = "interrupted"
TERMINAL = frozenset({COMPLETED, FAILED, INTERRUPTED})
ACTIVE = frozenset({QUEUED, RUNNING, WAITING_APPROVAL, STOP_REQUESTED})


@dataclass
class JobRecord:
    job_id: str
    session_id: str = ""
    turn_id: str = ""
    kind: str = ""
    target: str = ""
    status: str = QUEUED
    owner_pid: int = 0
    created_at: float = 0.0
    started_at: float = 0.0
    finished_at: float = 0.0
    stop_requested: bool = False
    progress: Dict[str, Any] = field(default_factory=dict)
    error: str = ""
    summary_ref: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)
    schema: str = SCHEMA

    def is_terminal(self) -> bool:
        return self.status in TERMINAL

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, doc: Dict[str, Any]) -> "JobRecord":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in doc.items() if k in known})


def pid_alive(pid: int) -> bool:
    """Best-effort liveness check for another process id."""
    if not pid or pid <= 0:
        return False
    if os.name == "nt":
        import ctypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, int(pid))
        if not handle:
            return False
        try:
            code = ctypes.c_ulong()
            if kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return code.value == STILL_ACTIVE
            return True
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def new_job_id() -> str:
    return f"J-{int(time.time() * 1000)}-{secrets.token_hex(3)}"


def _replace_with_retry(staged: Path, path: Path, *, attempts: int = 25,
                        delay: float = 0.01) -> None:
    """``os.replace`` 在 Windows 上会因目标文件正被打开而抛 PermissionError。

    读侧是刻意无锁的(见模块 docstring),所以"写替换"与"读打开"天然会重叠 ——
    负载一高这个窗口就会被撞上。重试到超时为止,而不是让一次正常的并发读把
    写操作打挂。
    """
    for remaining in range(attempts, 0, -1):
        try:
            os.replace(staged, path)
            return
        except PermissionError:
            if remaining == 1:
                raise
            time.sleep(delay)


class JobRegistry:
    """File-backed job records under ``<root>/jobs/<job_id>.json``."""

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)

    def _path(self, job_id: str) -> Path:
        return self.root / f"{job_id}.json"

    def _lock(self, job_id: str) -> AdvisoryFileLock:
        return AdvisoryFileLock(self.root / f"{job_id}.json.lock")

    def _write(self, record: JobRecord) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        path = self._path(record.job_id)
        staged = path.with_name("." + path.name + ".tmp")
        staged.write_text(json.dumps(record.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        _replace_with_retry(staged, path)

    # -- API -----------------------------------------------------------------
    def create(self, *, session_id: str = "", turn_id: str = "", kind: str = "",
               target: str = "", payload: Optional[Dict[str, Any]] = None) -> JobRecord:
        record = JobRecord(
            job_id=new_job_id(), session_id=session_id, turn_id=turn_id, kind=kind,
            target=target, status=QUEUED, owner_pid=os.getpid(),
            created_at=time.time(), payload=dict(payload or {}),
        )
        with self._lock(record.job_id):
            self._write(record)
        return record

    def get(self, job_id: str) -> Optional[JobRecord]:
        try:
            doc = json.loads(self._path(job_id).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return JobRecord.from_dict(doc) if isinstance(doc, dict) else None

    def list(self, *, session_id: str = "", limit: int = 50, active_only: bool = False) -> List[JobRecord]:
        if not self.root.is_dir():
            return []
        records: List[JobRecord] = []
        for path in self.root.glob("*.json"):
            try:
                doc = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if not isinstance(doc, dict):
                continue
            record = JobRecord.from_dict(doc)
            if session_id and record.session_id != session_id:
                continue
            if active_only and record.status not in ACTIVE:
                continue
            records.append(record)
        records.sort(key=lambda r: r.created_at, reverse=True)
        return records[:limit] if limit > 0 else records

    def update(self, job_id: str, **fields: Any) -> Optional[JobRecord]:
        with self._lock(job_id):
            record = self.get(job_id)
            if record is None:
                return None
            for key, value in fields.items():
                if key in JobRecord.__dataclass_fields__:  # type: ignore[attr-defined]
                    setattr(record, key, value)
            if fields.get("status") in TERMINAL and not record.finished_at:
                record.finished_at = time.time()
            self._write(record)
            return record

    def request_stop(self, job_id: str) -> Optional[JobRecord]:
        """Durable stop flag. Survives a crash, so a stop issued pre-crash wins."""
        with self._lock(job_id):
            record = self.get(job_id)
            if record is None:
                return None
            record.stop_requested = True
            if not record.is_terminal():
                record.status = STOP_REQUESTED
            self._write(record)
            return record

    def stop_requested(self, job_id: str) -> bool:
        record = self.get(job_id)
        return bool(record and record.stop_requested)

    def recover(self, *, is_alive: Callable[[int], bool] = pid_alive,
                auto_resume: bool = False) -> List[JobRecord]:
        """Fix up jobs whose owner process is gone. Returns the changed records."""
        changed: List[JobRecord] = []
        for record in self.list(limit=0):
            if record.status not in (RUNNING, STOP_REQUESTED):
                continue
            if is_alive(record.owner_pid):
                continue
            if record.stop_requested:
                updated = self.update(record.job_id, status=FAILED, error="stopped",
                                      progress={**record.progress, "recovered": True})
            elif auto_resume:
                updated = self.update(record.job_id, status=QUEUED, owner_pid=0,
                                      error="", progress={**record.progress, "requeued": True})
            else:
                updated = self.update(record.job_id, status=INTERRUPTED,
                                      error="owner_process_gone",
                                      progress={**record.progress, "recovered": True})
            if updated is not None:
                changed.append(updated)
        return changed


__all__ = [
    "JobRecord", "JobRegistry", "new_job_id", "pid_alive",
    "QUEUED", "RUNNING", "WAITING_APPROVAL", "STOP_REQUESTED",
    "COMPLETED", "FAILED", "INTERRUPTED", "TERMINAL", "ACTIVE", "SCHEMA",
]
