"""A directory the operator can drop a scope document into.

Dropping a file is a *proposal*, never an authorisation: the scan mints a pending
confirmation card in the conversation and stops there.  The other two entry points
(paste, upload) go through the same preview/confirm gate, so this one has no second
set of rules — and it must not become the one path where dropping a file is the
whole consent gesture.

The scan never creates a job.  That invariant is the reason this module may read
files at all.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

INBOX_DIR = "scope-inbox"
DEFAULT_INTERVAL_SECONDS = 5.0
INTERVAL_ENV = "LODE_SCOPE_INBOX_SECONDS"
REJECTS_FILE = "rejects.jsonl"
_REJECTS_LIMIT = 20


def interval_from_env() -> float:
    """How often to look.  Clamped so a typo cannot busy-loop or never fire."""
    raw = os.environ.get(INTERVAL_ENV, "")
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return DEFAULT_INTERVAL_SECONDS
    return max(0.5, min(value, 600.0))


class ScopeInbox:
    """Scan ``<state_dir>/scope-inbox/`` and mint one pending card per document.

    ``scan_once`` is deliberately synchronous and free of threads: the watcher is
    a thin loop around it, so the behaviour under test is the same behaviour the
    server runs.
    """

    def __init__(self, state_dir: Path | str, *, interval: Optional[float] = None) -> None:
        self.state_dir = Path(state_dir)
        self.root = self.state_dir / INBOX_DIR
        self.accepted_dir = self.root / "accepted"
        self.rejected_dir = self.root / "rejected"
        self.interval = interval if interval is not None else interval_from_env()
        # path → (size, mtime_ns) 上一次看到的样子。半写的文件必须等到它不再变化
        # 才处理,否则我们读到的是一份被截断的 JSON。
        self._seen: Dict[str, Tuple[int, int]] = {}

    def candidates(self) -> List[Path]:
        """Documents waiting at the top of the inbox.

        Only the top level, and never a symlink: ``accepted/`` and ``rejected/`` are
        where we put things, not where we read from.
        """
        if not self.root.is_dir():
            return []
        return sorted(path for path in self.root.glob("*.json")
                      if path.is_file() and not path.is_symlink())

    def scan_once(self, *, now: Optional[float] = None) -> Dict[str, Any]:
        report: Dict[str, Any] = {"accepted": [], "rejected": [], "waiting": []}
        for path in self.candidates():
            try:
                stat = path.stat()
            except OSError:
                continue
            fingerprint = (stat.st_size, stat.st_mtime_ns)
            key = str(path)
            if self._seen.get(key) != fingerprint:
                # 第一次看到,或者它还在被写:记下这一刻的样子,这一轮不动它。
                self._seen[key] = fingerprint
                report["waiting"].append(path.name)
                continue
            self._seen.pop(key, None)
            bucket, entry, retry = self._handle(path, now=now)
            if retry:
                self._seen[key] = fingerprint
            report[bucket].append(entry)
        return report

    # -- one file -------------------------------------------------------------
    def _handle(self, path: Path, *, now: Optional[float]) -> Tuple[str, Dict[str, Any], bool]:
        from agents import scope_document
        from console import intake as intake_bridge
        from core.intake_state import IntakeStateError

        name = path.name
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return self._reject(path, "scope_inbox_unreadable", "", now=now)
        try:
            preview = intake_bridge.start_scope_preview(self.state_dir, source="inbox", text=text)
        except IntakeStateError as exc:
            if str(exc) == "pending_intake_exists":
                # 槽被占着。这不是一份坏文档,所以不丢进 rejected/ —— 留着,等那一格
                # 空了下一轮自然会被收走。丢了等于让操作员白白再拖一次文件。
                return ("waiting", {"file": name, "reason": "pending_intake_exists"}, True)
            return self._reject(path, str(exc), "", now=now)
        except scope_document.ScopeDocumentError as exc:
            return self._reject(path, exc.reason, str(exc.detail or ""), now=now)
        except OSError:
            return self._reject(path, "scope_inbox_write_failed", "", now=now)

        self._move(path, self.accepted_dir)
        return ("accepted", {"file": name, "intake_id": preview.intake_id,
                             "hosts": len(preview.summary.get("hosts") or [])}, False)

    def _reject(self, path: Path, reason: str, detail: str,
                *, now: Optional[float]) -> Tuple[str, Dict[str, Any], bool]:
        """Move the file aside and record why — the operator has to learn the reason."""
        name = path.name
        record = {"file": name, "reason": reason, "detail": detail,
                  "ts": float(now if now is not None else time.time())}
        try:
            self.root.mkdir(parents=True, exist_ok=True)
            with (self.root / REJECTS_FILE).open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
            self._move(path, self.rejected_dir)
            (self.rejected_dir / f"{name}.reason.txt").write_text(
                f"{reason}\n" + (f"{detail}\n" if detail else ""), encoding="utf-8")
        except OSError:
            pass
        return ("rejected", {"file": name, "reason": reason, "detail": detail}, False)

    @staticmethod
    def _move(path: Path, target_dir: Path) -> None:
        target_dir.mkdir(parents=True, exist_ok=True)
        target = target_dir / path.name
        if target.exists():
            # 同名文件再拖一次不该覆盖上一次的下场 —— 那份记录是证据的一部分。
            for counter in range(1, 1000):
                candidate = target_dir / f"{path.stem}.{counter}{path.suffix}"
                if not candidate.exists():
                    target = candidate
                    break
        os.replace(path, target)

    def rejects(self, limit: int = _REJECTS_LIMIT) -> List[Dict[str, Any]]:
        """Recent refusals, newest last — so the UI can say why a drop did nothing."""
        path = self.root / REJECTS_FILE
        if not path.is_file():
            return []
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        out: List[Dict[str, Any]] = []
        for line in lines[-limit:]:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict):
                out.append(record)
        return out


async def watch(state_dir: Path | str, *, interval: Optional[float] = None,
                inbox: Optional[ScopeInbox] = None) -> None:
    """Scan forever.  A failure is reported by being absent, never by crashing."""
    inbox = inbox or ScopeInbox(state_dir, interval=interval)
    while True:
        try:
            inbox.scan_once()
        except Exception:  # noqa: BLE001 - 一个后台循环不能因为一次坏文件就死掉
            pass
        await asyncio.sleep(inbox.interval)


def start_watcher(state_dir: Path | str, *, interval: Optional[float] = None) -> "asyncio.Task[None]":
    """Start the watcher task and do one scan immediately.

    The immediate scan matters: a file already sitting in the inbox at start-up
    should not wait for the first interval.
    """
    inbox = ScopeInbox(state_dir, interval=interval)
    try:
        inbox.scan_once()
    except Exception:  # noqa: BLE001
        pass
    return asyncio.create_task(watch(state_dir, inbox=inbox))


__all__ = [
    "DEFAULT_INTERVAL_SECONDS", "INBOX_DIR", "INTERVAL_ENV", "ScopeInbox",
    "interval_from_env", "start_watcher", "watch",
]
