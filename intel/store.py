from __future__ import annotations

import json
import os
import tempfile
import csv
from pathlib import Path
from typing import Any, Iterator

from .locking import FileLock
from .models import AssetCandidate, RunReport


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.stem}-", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


class IntelStore:
    """Append-only run artifacts plus a compact historical key index."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.runs = self.root / "runs"
        self.history_path = self.root / "history.json"
        self.lock_path = self.root / "store.lock"
        self.watch_lock_path = self.root / "watch.lock"
        self.watch_state_path = self.root / "watch-state.json"

    def previous_keys(self) -> set[str]:
        try:
            value = json.loads(self.history_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return set()
        return {str(item) for item in value.get("keys", [])} if isinstance(value, dict) else set()

    def write(self, report: RunReport) -> Path:
        run_dir = self.runs / report.run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        with FileLock(self.lock_path):
            _atomic_json(run_dir / "run.json", report.to_dict())
            with (run_dir / "candidates.jsonl").open("w", encoding="utf-8", newline="\n") as handle:
                for candidate in report.candidates:
                    handle.write(json.dumps(candidate.to_dict(), ensure_ascii=False, sort_keys=True) + "\n")
            fields = ["value", "kind", "source", "sources", "observed_at", "published_at", "title", "summary", "confidence", "scope_status", "evidence_ref", "tags", "score", "is_new"]
            with (run_dir / "candidates.csv").open("w", encoding="utf-8-sig", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                for candidate in report.candidates:
                    row = candidate.to_dict()
                    row["sources"] = "|".join(row["sources"])
                    row["tags"] = "|".join(row["tags"])
                    writer.writerow({field: row.get(field, "") for field in fields})
            keys = self.previous_keys()
            keys.update(candidate.key for candidate in report.candidates)
            _atomic_json(self.history_path, {"schema": "IntelHistory/v1", "keys": sorted(keys)})
        return run_dir

    def write_watch_state(self, state: dict[str, Any]) -> None:
        with FileLock(self.lock_path):
            _atomic_json(self.watch_state_path, state)

    def read_watch_state(self) -> dict[str, Any]:
        try:
            value = json.loads(self.watch_state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return dict(value) if isinstance(value, dict) else {}

    def iter_candidates(self, run_id: str | None = None) -> Iterator[AssetCandidate]:
        path = self.runs / run_id / "candidates.jsonl" if run_id else None
        paths = [path] if path else sorted(self.runs.glob("*/candidates.jsonl"))
        for item in paths:
            if item is None or not item.is_file() or item.is_symlink():
                continue
            for line in item.read_text(encoding="utf-8").splitlines():
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(value, dict):
                    yield AssetCandidate.from_mapping(value)
