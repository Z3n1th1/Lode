"""Durable metadata-only queue for the optional intelligence digest."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from core.confidentiality import sanitize_external_text
from core.file_lock import AdvisoryFileLock
from .models import RunReport
from .store import _atomic_json


class FeishuOutbox:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.path = self.root / "feishu-outbox.json"
        self.lock_path = self.root / "feishu-outbox.lock"
        if any(path.is_symlink() for path in (self.root, self.path, self.lock_path)):
            raise ValueError("feishu_outbox_symlink_rejected")

    def lock(self) -> AdvisoryFileLock:
        return AdvisoryFileLock(self.lock_path, timeout_seconds=30)

    def read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"schema": "FeishuIntelOutbox/v1", "pending": {}, "delivered": []}
        state = json.loads(self.path.read_text(encoding="utf-8"))
        if (not isinstance(state, dict) or state.get("schema") != "FeishuIntelOutbox/v1"
                or not isinstance(state.get("pending"), dict)
                or not isinstance(state.get("delivered"), list)
                or any(not isinstance(key, str) for key in state["delivered"])
                or any(not isinstance(row, dict) or not isinstance(row.get("program"), str)
                       or not isinstance(row.get("line"), str)
                       for row in state["pending"].values())):
            raise ValueError("feishu_outbox_invalid")
        return state

    def write(self, state: dict[str, Any]) -> None:
        _atomic_json(self.path, state)

    @staticmethod
    def enqueue(state: dict[str, Any], report: RunReport, *, program: str, min_score: float) -> int:
        delivered = set(state["delivered"])
        added = 0
        for item in report.candidates:
            if not item.is_new or item.score < min_score or item.scope_status != "in_scope":
                continue
            key = hashlib.sha256((program + "\0" + item.key).encode("utf-8")).hexdigest()
            if key in state["pending"] or key in delivered:
                continue
            title = sanitize_external_text((item.title or item.value).replace("\n", " "), limit=120)
            value = sanitize_external_text(item.value.replace("\n", " "), limit=300)
            source = sanitize_external_text(item.source.replace("\n", " "), limit=100)
            summary = sanitize_external_text(item.summary.replace("\n", " "), limit=220)
            line = f"{title} · {value} · score={item.score:.0f} · source={source}"
            if summary and summary != title:
                line += f"\n摘要: {summary}"
            state["pending"][key] = {"program": program, "line": line,
                                     "enqueued_at": report.completed_at, "run_id": report.run_id}
            added += 1
        return added

    @staticmethod
    def batch(state: dict[str, Any], *, program: str, max_items: int) -> list[tuple[str, dict[str, Any]]]:
        # Keep complete entries inside the notifier's 1,000-character body cap.
        rows = [(key, row) for key, row in state["pending"].items() if row["program"] == program]
        rows.sort(key=lambda pair: (pair[1].get("enqueued_at", ""), pair[0]))
        batch = []
        length = 0
        for key, row in rows:
            next_length = length + len(row["line"]) + bool(batch)
            if len(batch) >= max_items or next_length > 1000:
                break
            batch.append((key, row))
            length = next_length
        return batch

    @staticmethod
    def acknowledge(state: dict[str, Any], batch: list[tuple[str, dict[str, Any]]]) -> None:
        delivered = set(state["delivered"])
        for key, _row in batch:
            state["pending"].pop(key, None)
            delivered.add(key)
        state["delivered"] = sorted(delivered)
