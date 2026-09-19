"""Record a run that already happened into the Console's task ledger.

``Console`` views its work through ``state_dir/strix_tasks.jsonl``: that is what
``projections.projects()`` / ``project_detail()`` fold into 项目 → tasks, and what
``_task_dirs()`` resolves an ``output_path`` from.  In this repo the only writer
was the external orchestrator (``notify/feishu_reply_consumer.py``), so a surface
scan run from ``lode.py`` produced files under ``--out-dir`` and nothing at all in
the Console — the two never met.

This module is that bridge.  One run, one row, in the shape the projections
already validate (see ``console/deps.py`` for ``TASK_ID_RE`` and
``ALLOWED_TASK_STATUSES`` — note the ledger says ``finished``, not ``completed``;
a row with an unknown status keeps the default and looks like it never started).

What it deliberately does **not** do: write ``strix_runs/*/findings.sarif`` or
``standard_report_cn.md``.  A surface scan produces an attack surface, not
vulnerabilities and not a pentest report.  Faking either would put an unearned
finding on a screen whose whole purpose is to be trusted.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

LEDGER_NAME = "strix_tasks.jsonl"

# ``lode.py console`` runs with the repo root on sys.path, other callers with
# ``core/`` on it. Same fallback dance as core/event_log.py — guessing the root
# from the ledger path only worked while state_dir sat one level under the repo.
try:
    from core.file_lock import AdvisoryFileLock
except ImportError:  # pragma: no cover - depends on how the process was started
    from file_lock import AdvisoryFileLock  # type: ignore


def ledger_path(state_dir: Path | str) -> Path:
    return Path(state_dir) / LEDGER_NAME


def _lock(path: Path) -> AdvisoryFileLock:
    return AdvisoryFileLock(path.with_name(path.name + ".lock"))


def load_rows(state_dir: Path | str) -> List[Dict[str, Any]]:
    """Every readable row. Tolerates a truncated tail, same as the projections."""
    path = ledger_path(state_dir)
    try:
        raw = path.read_bytes()
    except OSError:
        return []
    rows: List[Dict[str, Any]] = []
    for line in raw.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue  # 末行可能因为进程被杀而残缺
        if isinstance(row, dict):
            rows.append(row)
    return rows


def _next_task_id(taken: set) -> str:
    """``T-<digits>``.  The projections only accept that shape; a free-form id is
    dropped silently, which is how a run "disappears"."""
    candidate = int(time.time() * 1000)
    while f"T-{candidate}" in taken:
        candidate += 1
    return f"T-{candidate}"


def record_run(
    state_dir: Path | str,
    *,
    target: str,
    output_path: Path | str,
    run_id: str = "",
    status: str = "finished",
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Append one finished run for ``target`` and return the row written."""
    from console.deps import ALLOWED_TASK_STATUSES  # noqa: PLC0415

    ledger = ledger_path(state_dir)
    ledger.parent.mkdir(parents=True, exist_ok=True)
    with _lock(ledger):
        taken = {row.get("id") for row in load_rows(state_dir)}
        task_id = _next_task_id(taken)
        now = time.time()
        row: Dict[str, Any] = {
            "id": task_id,
            "target": str(target),
            # 没有外部 profile:投影侧 require_profile=False,界面显示 "—"。
            # 填一个假的比留空更糟 —— 那会让人以为它走过 profile 那条链。
            "profile_name": "",
            "goal_id": "",
            "status": status if status in ALLOWED_TASK_STATUSES else "finished",
            "run_id": run_id or f"surface-{task_id}",
            "output_path": str(Path(output_path).resolve()),
            "created_ts": now,
            "finished_ts": now,
        }
        if extra:
            row.update({k: v for k, v in extra.items() if k not in row})
        with ledger.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
    return row


__all__ = ["LEDGER_NAME", "ledger_path", "load_rows", "record_run"]
