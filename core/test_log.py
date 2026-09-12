"""SRC test progress tracker — persistent log of all testing activity.

Records: targets tested, endpoints explored, findings, dead ends, time spent.
Provides a dashboard summary for WebUI and CLI.

Storage: JSONL append-only log + periodic summary JSON.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


SCHEMA = "SrcTestLog/v1"
SUMMARY_SCHEMA = "SrcTestSummary/v1"


@dataclass
class TestEvent:
    """One logged event. Named TestEvent for domain language; excluded from pytest collection."""
    __test__ = False  # tell pytest this is not a test class
    kind: str  # scan_start, scan_complete, explore_start, explore_complete, finding, dead_end, error, operator_action
    target: str = ""
    url: str = ""
    detail: str = ""
    finding_type: str = ""
    confidence: str = ""
    evidence: str = ""
    worker_id: str = ""
    ts: float = field(default_factory=time.time)


class SrcTestLog:
    """Append-only test log with summary projection."""

    def __init__(self, state_dir: str | Path) -> None:
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.state_dir / "src-test-log.jsonl"
        self.summary_path = self.state_dir / "src-test-summary.json"

    def log(self, event: TestEvent) -> None:
        """Append one event to the log."""
        line = json.dumps({"schema": SCHEMA, **asdict(event)}, ensure_ascii=False)
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

    def log_dict(self, data: Dict[str, Any]) -> None:
        """Append a raw dict event."""
        data.setdefault("schema", SCHEMA)
        data.setdefault("ts", time.time())
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(data, ensure_ascii=False) + "\n")

    def recent(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Read the last N events."""
        if not self.log_path.is_file():
            return []
        events = []
        for line in self.log_path.read_text(encoding="utf-8").splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return events[-limit:]

    def summary(self) -> Dict[str, Any]:
        """Compute a full summary from the log."""
        events = self.recent(10000)
        targets_scanned: Dict[str, Dict[str, Any]] = {}
        urls_explored: Dict[str, str] = {}  # url -> status
        findings: List[Dict[str, Any]] = []
        dead_ends: List[Dict[str, Any]] = []
        errors: List[str] = []
        total_scans = 0
        total_explores = 0
        total_findings = 0
        total_dead_ends = 0
        first_ts = 0.0
        last_ts = 0.0

        for e in events:
            ts = e.get("ts", 0)
            if not first_ts or ts < first_ts:
                first_ts = ts
            if ts > last_ts:
                last_ts = ts

            kind = e.get("kind", "")
            target = e.get("target", "")

            if kind == "scan_start" and target:
                if target not in targets_scanned:
                    targets_scanned[target] = {"first_scan": ts, "scans": 0, "findings": 0, "dead_ends": 0}
                targets_scanned[target]["scans"] += 1
                total_scans += 1

            elif kind == "scan_complete" and target:
                if target in targets_scanned:
                    targets_scanned[target]["last_scan"] = ts
                    targets_scanned[target]["paths"] = e.get("paths", 0)
                    targets_scanned[target]["intents"] = e.get("intents", 0)

            elif kind == "explore_complete":
                url = e.get("url", "")
                status = e.get("detail", "")
                if url:
                    urls_explored[url] = status
                total_explores += 1

            elif kind == "finding":
                findings.append({
                    "target": target,
                    "url": e.get("url", ""),
                    "type": e.get("finding_type", ""),
                    "confidence": e.get("confidence", ""),
                    "evidence": e.get("evidence", "")[:300],
                    "detail": e.get("detail", "")[:300],
                    "ts": ts,
                })
                total_findings += 1
                if target in targets_scanned:
                    targets_scanned[target]["findings"] = targets_scanned[target].get("findings", 0) + 1

            elif kind == "dead_end":
                dead_ends.append({
                    "url": e.get("url", ""),
                    "reason": e.get("detail", "")[:200],
                    "ts": ts,
                })
                total_dead_ends += 1
                if target in targets_scanned:
                    targets_scanned[target]["dead_ends"] = targets_scanned[target].get("dead_ends", 0) + 1

            elif kind == "error":
                errors.append(e.get("detail", "")[:200])

        result = {
            "schema": SUMMARY_SCHEMA,
            "generated_at": time.time(),
            "time_range": {"first": first_ts, "last": last_ts,
                           "duration_hours": round((last_ts - first_ts) / 3600, 2) if first_ts else 0},
            "totals": {
                "targets": len(targets_scanned),
                "scans": total_scans,
                "urls_explored": len(urls_explored),
                "total_explores": total_explores,
                "findings": total_findings,
                "dead_ends": total_dead_ends,
                "errors": len(errors),
            },
            "targets": targets_scanned,
            "findings": findings[-50:],
            "pending_urls": [u for u, s in urls_explored.items() if s == "queued"],
            "recent_dead_ends": dead_ends[-20:],
            "recent_errors": errors[-10:],
        }

        # Write summary to file
        try:
            self.summary_path.write_text(
                json.dumps(result, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except OSError:
            pass

        return result
