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

A run that takes a while is two rows, not one: ``begin_run`` writes the opening
``running`` row and ``finish_run`` appends the closing row **with the same id**.
``_project_tasks`` folds by id and the later event wins, so the two collapse into
one task — and in between, the Console can actually see that something is running.
``record_run`` stays for callers that only ever have a finished run to report.

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


def _append_row(ledger: Path, row: Dict[str, Any]) -> None:
    """Append one row. The caller holds the advisory lock."""
    with ledger.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")


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
        _append_row(ledger, row)
    return row


def begin_run(
    state_dir: Path | str,
    *,
    target: str,
    output_path: Path | str,
    run_id: str = "",
    goal_id: str = "",
    batch_index: int = 0,
    batch_size: int = 0,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Append the OPENING row of a run, so the Console can show it while it works.

    ``record_run`` writes its only row *after* the fact, which is why an in-flight
    target was invisible: by the time the projections saw anything, it already
    said ``finished``.  This writes ``running`` up front and the matching
    ``finish_run`` closes it out.

    **No ``finished_ts`` here.**  The fold treats that key's mere presence as
    "this run ended", so writing it would defeat the whole point.

    ``batch_index``/``batch_size`` are the run's position in a multi-target
    invocation (1-based), so the UI can say "137/325" instead of a bare spinner.
    """
    from console.deps import ALLOWED_TASK_STATUSES  # noqa: PLC0415

    ledger = ledger_path(state_dir)
    ledger.parent.mkdir(parents=True, exist_ok=True)
    with _lock(ledger):
        rows = load_rows(state_dir)
        task_id = _next_task_id({row.get("id") for row in rows})
        now = time.time()
        # 进程被 SIGKILL 打断时,同一 target 的 running 行没人来收尾。同一把锁里
        # 就地补一条 interrupted —— 否则界面上会永远留着一行假的"在跑"。
        stale = {
            str(row.get("id"))
            for row in rows
            if row.get("status") == "running" and str(row.get("target")) == str(target)
        }
        for stale_id in sorted(stale):
            _append_row(ledger, {"id": stale_id, "status": "interrupted",
                                 "finished_ts": now, "error": "superseded_by_rescan"})
        row: Dict[str, Any] = {
            "id": task_id,
            "target": str(target),
            "profile_name": "",
            "goal_id": str(goal_id or ""),
            "status": "running" if "running" in ALLOWED_TASK_STATUSES else "reserved",
            "run_id": run_id or f"surface-{task_id}",
            "output_path": str(Path(output_path).resolve()),
            "created_ts": now,
            "batch_index": max(0, int(batch_index)),
            "batch_size": max(0, int(batch_size)),
        }
        if extra:
            row.update({k: v for k, v in extra.items() if k not in row})
        _append_row(ledger, row)
    return row


def finish_run(
    state_dir: Path | str,
    *,
    task_id: str,
    status: str = "finished",
    target: str = "",
    output_path: Path | str | None = None,
    goal_id: str = "",
    error: str = "",
    surface: Optional[Dict[str, Any]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Append the CLOSING row for a run opened by :func:`begin_run`, same id.

    Deliberately omits ``created_ts``: the fold only overwrites ``created_at``
    when the key is present, so the project's 最近活动 stays at scan *start* rather
    than jumping forward at the end.

    Empty values are dropped rather than written, because the fold only overwrites
    ``target``/``goal_id`` when the new value is truthy — sending ``""`` would be a
    no-op anyway, and sending ``None`` would overwrite a real path with nothing.

    ``surface`` takes the counters ``surface_to_dict`` already produces
    (``paths``/``api_urls``/``scripts``/``status``); a caller that has no surface
    (``auto`` produces candidates, not a crawl) simply omits it and the UI shows
    "—" instead of a fabricated 0.

    No id-shape validation: ``task_id`` always comes from :func:`begin_run`, and
    raising from here would usually be raising out of a ``finally``, masking the
    real error.
    """
    from console.deps import ALLOWED_TASK_STATUSES  # noqa: PLC0415

    ledger = ledger_path(state_dir)
    ledger.parent.mkdir(parents=True, exist_ok=True)
    row: Dict[str, Any] = {
        "id": str(task_id),
        "status": status if status in ALLOWED_TASK_STATUSES else "finished",
        "finished_ts": time.time(),
    }
    if target:
        row["target"] = str(target)
    if goal_id:
        row["goal_id"] = str(goal_id)
    if output_path is not None:
        row["output_path"] = str(Path(output_path).resolve())
    if error:
        row["error"] = str(error)[:400]
    if surface:
        row["surface_paths"] = max(0, int(surface.get("paths") or 0))
        row["surface_api"] = max(0, int(surface.get("api_urls") or 0))
        row["surface_scripts"] = max(0, int(surface.get("scripts") or 0))
        row["http_status"] = max(0, int(surface.get("status") or 0))
    if extra:
        row.update({k: v for k, v in extra.items() if k not in row})
    with _lock(ledger):
        _append_row(ledger, row)
    return row


__all__ = ["LEDGER_NAME", "ledger_path", "load_rows", "record_run",
           "begin_run", "finish_run"]
