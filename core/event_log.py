"""Append-only per-session event log (the unified conversation/journal stream).

One JSONL file per session, monotonic ``seq`` assigned under an advisory lock.
Chat turns, subtask lifecycle, tool calls, findings and approval gates all write
the same shape, so a renderer is a pure ``seq``-ordered fold — that is what lets
a launched subtask stream inline into the conversation.

Event shape::

    {"seq": 42, "ts": 1757..., "session_id": "src-...", "turn_id": "T-...",
     "agent_id": "root", "kind": "...", /* kind-specific payload */}

Reads are lock-free and tolerant of a partially written trailing line.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

try:  # package import (python -m console.server)
    from core.file_lock import AdvisoryFileLock
except ImportError:  # pragma: no cover - stripped checkout with core/ on sys.path
    from file_lock import AdvisoryFileLock  # type: ignore

MAX_EVENT_BYTES = 64 * 1024
DEFAULT_LIMIT = 500

# 信封字段由 append 自己写。`session_id`/`turn_id`/`agent_id`/`kind` 都是形参,
# 载荷里带同名键会直接 TypeError(参数重复);只有 `seq`/`ts` 是计算出来的,能被
# 载荷一路传进来覆盖掉事件的序号与时间戳 —— 这里挡住它们。
_ENVELOPE_KEYS = frozenset({"seq", "ts"})

EVENT_KINDS = (
    "user_message", "assistant_message", "assistant_delta", "reasoning",
    "tool_call", "tool_result", "subtask_started", "subtask_progress",
    "subtask_finished", "finding", "approval_required", "approval_resolved",
    "mode_changed", "error",
)


class EventLog:
    """Append-only event journal for one session."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.lock_path = self.path.with_name(self.path.name + ".lock")

    # -- reads (lock-free) ---------------------------------------------------
    def _iter_events(self) -> List[Dict[str, Any]]:
        if not self.path.is_file():
            return []
        events: List[Dict[str, Any]] = []
        try:
            raw = self.path.read_text(encoding="utf-8")
        except OSError:
            return []
        for line in raw.split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                doc = json.loads(line)
            except ValueError:
                continue  # tolerate a truncated trailing write
            if isinstance(doc, dict):
                events.append(doc)
        return events

    def max_seq(self) -> int:
        seqs = [int(e.get("seq") or 0) for e in self._iter_events()]
        return max(seqs) if seqs else 0

    def since(self, seq: int, *, limit: int = DEFAULT_LIMIT) -> List[Dict[str, Any]]:
        """Events with ``seq > seq``, oldest first, capped to the last ``limit``."""
        out = [e for e in self._iter_events() if int(e.get("seq") or 0) > int(seq)]
        return out[-limit:] if limit > 0 else out

    def tail(self, n: int = 50) -> List[Dict[str, Any]]:
        events = self._iter_events()
        return events[-n:] if n > 0 else events

    # -- writes --------------------------------------------------------------
    def append(self, kind: str, *, session_id: str = "", turn_id: str = "",
               agent_id: str = "root", **payload: Any) -> Dict[str, Any]:
        """Append one event and return it. ``seq`` is assigned under the lock."""
        with AdvisoryFileLock(self.lock_path):
            seq = self.max_seq() + 1
            event: Dict[str, Any] = {
                "seq": seq,
                "ts": time.time(),
                "session_id": session_id,
                "turn_id": turn_id,
                "agent_id": agent_id,
                "kind": kind,
            }
            event.update({k: v for k, v in payload.items() if k not in _ENVELOPE_KEYS})
            line = json.dumps(event, ensure_ascii=False, default=str)
            if len(line) > MAX_EVENT_BYTES:
                line = json.dumps({**event, "_truncated": True}, ensure_ascii=False, default=str)[:MAX_EVENT_BYTES]
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        return event


def load_events(path: Path | str, *, since: int = 0, limit: int = DEFAULT_LIMIT) -> List[Dict[str, Any]]:
    """Convenience reader for a session's event file."""
    return EventLog(path).since(since, limit=limit)


__all__ = ["EventLog", "EVENT_KINDS", "load_events", "DEFAULT_LIMIT"]
