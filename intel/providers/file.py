from __future__ import annotations

import csv
import json
from pathlib import Path

from ..models import AssetCandidate, IntelQuery, utc_now


class FileProvider:
    def __init__(self, path: str | Path, *, source_id: str = "file") -> None:
        self.path = Path(path)
        self.id = f"{source_id}:{self.path.name}"

    def collect(self, query: IntelQuery, *, timeout: float, max_items: int) -> list[AssetCandidate]:
        del query, timeout
        if self.path.is_symlink() or not self.path.is_file():
            raise ValueError("intel_input_file_missing_or_symlink")
        if self.path.stat().st_size > 20_000_000:
            raise ValueError("intel_input_file_too_large")
        text = self.path.read_text(encoding="utf-8")
        rows: list[object]
        if self.path.suffix.lower() == ".csv":
            rows = list(csv.DictReader(text.splitlines()))
        elif self.path.suffix.lower() == ".jsonl":
            rows = [json.loads(line) for line in text.splitlines() if line.strip()]
        else:
            decoded = json.loads(text)
            rows = decoded if isinstance(decoded, list) else [decoded]
        result: list[AssetCandidate] = []
        for row in rows:
            if isinstance(row, str):
                value, kind = row.strip(), "url" if "://" in row else "hostname"
                row = {"value": value, "kind": kind}
            if not isinstance(row, dict):
                continue
            candidate = AssetCandidate.from_mapping({**row, "source": str(row.get("source") or self.id), "observed_at": row.get("observed_at") or utc_now()})
            if candidate.value:
                result.append(candidate)
            if len(result) >= max_items:
                break
        return result
