"""Console job service: durable registry + runner + session event sink.

Single place that owns the process-wide :class:`JobRegistry` /
:class:`JobRunner` pair (one per state dir) and routes job lifecycle events into
the session's :class:`EventLog`, so a launched subtask streams inline into the
conversation. Feishu notification on terminal state is best-effort and fully
guarded — it must never fail a job.
"""
from __future__ import annotations

import json
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from core.file_lock import replace_with_retry
from core.event_log import EventLog
from core.intake_state import IntakeStateError
from core.job_registry import ACTIVE, JobRecord, JobRegistry
from core.job_runner import JobContext, JobRunner

_LOCK = threading.Lock()
_ENTRIES: Dict[str, Dict[str, Any]] = {}
_NOTIFY_STATE: Dict[str, Any] = {"tried": False, "fn": None}


def session_dir(state_dir: Path | str, session_id: str) -> Path:
    return Path(state_dir) / "src-chat" / session_id


def events_path(state_dir: Path | str, session_id: str) -> Path:
    return session_dir(state_dir, session_id) / "events.jsonl"


def get_log(state_dir: Path | str, session_id: str) -> EventLog:
    return EventLog(events_path(state_dir, session_id))


# -- job handlers ------------------------------------------------------------
def _run_scope(job: JobRecord, ctx: JobContext, scope: Any, *, run_id: str, target_url: str) -> Dict[str, Any]:
    """The work itself: one autopilot round, then the LLM agent loop.

    Split out of the handlers because *which* engagements are allowed is decided
    by the caller (a URL typed into the conversation vs a confirmed TargetCard),
    while what happens afterwards is the same.
    """
    from agents.src_agent import run_src_agent
    from agents.src_autopilot import SrcAutopilot

    state_dir = Path(ctx.job.payload.get("_state_dir") or ".")
    out_dir = state_dir / "src-agent-runs" / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    bb_path = out_dir / "src-blackboard.json"
    reasoner = (job.payload.get("reasoner_prefer") or "").strip() or os.environ.get("SRC_REASONER_PREFER", "").strip()
    explorer = (job.payload.get("explorer_prefer") or "").strip() or os.environ.get("SRC_EXPLORER_PREFER", "").strip()

    try:
        scope_doc = {
            "schema": "SrcRunScope/v1", "run_id": run_id, "program": scope.program,
            "authorization": scope.authorization, "allowed_domains": list(scope.allowed_domains),
            "allowed_hosts": list(scope.allowed_hosts), "reasoner_prefer": reasoner,
            "explorer_prefer": explorer, "created_at": time.time(),
        }
        staged = out_dir / ".scope.json.tmp"
        staged.write_text(json.dumps(scope_doc, ensure_ascii=False, indent=2), encoding="utf-8")
        replace_with_retry(staged, out_dir / "scope.json")
    except OSError:
        pass

    ctx.emit("subtask_progress", phase="autopilot")
    autopilot = SrcAutopilot(scope, out_dir / "autopilot-state.json", out_dir,
                             max_rounds=3, max_candidates=100, blackboard_path=bb_path)
    autopilot.run_round([target_url])
    if ctx.stopped():
        return {"progress": {"phase": "stopped"}}

    ctx.emit("subtask_progress", phase="reason_explore")
    summary = run_src_agent(
        bb_path, scope,
        max_cycles=int(job.payload.get("max_cycles") or 20),
        max_explore_per_cycle=int(job.payload.get("max_explore") or 3),
        reasoner_prefer=reasoner, explorer_prefer=explorer,
        worker_id=f"console-{run_id}",
    )
    findings = 0
    if isinstance(summary, dict):
        findings = int(summary.get("findings") or summary.get("total_findings") or 0)
    ctx.emit("subtask_progress", phase="done", findings=findings)
    return {"summary_ref": str(bb_path), "progress": {"phase": "done", "findings": findings}}


def _handler_src_loop(job: JobRecord, ctx: JobContext) -> Dict[str, Any]:
    """Full SRC pipeline for a target typed into the conversation.

    The scope is widened to the target's registrable domain: here the operator
    typed a URL and the engagement profile decides how far to go.  A confirmed
    TargetCard must **not** take this path — see
    :func:`_scope_from_confirmed_card`.
    """
    from agents.surface_discovery import SurfaceScope
    from urllib.parse import urlparse

    run_id = str(ctx.job.payload.get("run_id") or job.job_id)
    target_url = job.target

    parsed = urlparse(target_url)
    host = (parsed.hostname or "").lower()
    domains = [str(d).strip() for d in (job.payload.get("allowed_domains") or []) if str(d).strip()]
    hosts = [str(h).strip().lower() for h in (job.payload.get("allowed_hosts") or []) if str(h).strip()]
    if host and host not in domains and host not in hosts:
        parts = host.split(".")
        domains.append(".".join(parts[-2:]) if len(parts) >= 2 else host)

    authorization = str(job.payload.get("authorization") or "")
    scope = SurfaceScope(
        program=f"console-{run_id}",
        authorization=authorization or f"Console operator authorized scan of {target_url}",
        allowed_domains=tuple(domains), allowed_hosts=tuple(hosts), delay_seconds=0.5,
    )
    return _run_scope(job, ctx, scope, run_id=run_id, target_url=target_url)


TARGET_RUN_KIND = "target_run"


def _scope_from_confirmed_card(card: Dict[str, Any], *, target_id: str, run_id: str) -> Any:
    """Build the run scope from a confirmed TargetCard — strictly.

    ``allowed_domains`` stays empty on purpose: a domain entry matches
    descendants, so widening a one-host card to its registrable domain would let
    the run reach hosts the operator never confirmed.  Non-wildcard
    ``allowed_hosts`` entries match exactly, which is what a card carries.
    """
    from agents.surface_discovery import SurfaceScope

    data = card.get("scope") if isinstance(card.get("scope"), dict) else {}
    hosts = tuple(str(item).strip() for item in (data.get("allowed_hosts") or []) if str(item).strip())
    forbidden = tuple(str(item).strip() for item in (data.get("forbidden_hosts") or []) if str(item).strip())
    return SurfaceScope(
        program=f"console-{run_id}",
        authorization=f"confirmed_target_card:{target_id}",
        allowed_domains=(),
        allowed_hosts=hosts,
        forbidden=forbidden,
    )


def _handler_target_run(job: JobRecord, ctx: JobContext) -> Dict[str, Any]:
    """Run one confirmed TargetCard.

    The card defines the scope, and its digest is re-checked here: the operator
    confirmed a specific object, so a card edited between confirmation and run
    has to fail rather than quietly authorise something else.
    """
    from console import intake as _intake

    target_id = str(job.payload.get("target_id") or "")
    run_id = str(job.payload.get("run_id") or job.job_id)
    stored = _intake.target_cards(None).load(
        target_id, expected_digest=str(job.payload.get("target_card_digest") or ""))
    if stored["target_card_ref"] != str(job.payload.get("target_card_ref") or ""):
        raise IntakeStateError("target_card_ref_mismatch")
    scope = _scope_from_confirmed_card(stored["target_card"], target_id=target_id, run_id=run_id)
    # Belt and braces: the card has to cover the URL we are about to fetch.
    allowed, reason = scope.check_url(job.target)
    if not allowed:
        raise IntakeStateError(f"target_not_in_confirmed_scope:{reason}")
    return _run_scope(job, ctx, scope, run_id=run_id, target_url=job.target)


def start_target_run(
    state_dir: Path | str,
    *,
    confirmed: Dict[str, Any],
    session_id: str = "",
) -> Dict[str, Any]:
    """Start the run a consumed confirmation authorises.  Idempotent per intake.

    Only ever called with a receipt in hand, so the card this job re-reads and
    digest-checks is already the confirmed one.  A repeated call — double click, a
    replayed POST — returns the job that is already running instead of starting a
    second run of the same confirmation.
    """
    registry = get_registry(state_dir)
    intake_id = str(confirmed.get("intake_id") or "")
    existing = next(
        (record for record in registry.list(limit=0)
         if record.kind == TARGET_RUN_KIND
         and str(record.payload.get("intake_id") or "") == intake_id),
        None,
    )
    if existing is not None:
        return {"session_id": existing.session_id, "job_id": existing.job_id, "reused": True}

    session_id = session_id or f"src-{secrets.token_hex(6)}"
    instruction = str(confirmed.get("instruction") or "")
    job = registry.create(
        session_id=session_id, turn_id=f"T-{secrets.token_hex(4)}", kind=TARGET_RUN_KIND,
        target=str(confirmed.get("target") or ""),
        payload={
            "_state_dir": str(state_dir),
            "run_id": f"SL-{int(time.time())}-{secrets.token_hex(3)}",
            "via": "console_intake",
            "intake_id": intake_id,
            "options_digest": str(confirmed.get("options_digest") or ""),
            "target_id": str(confirmed.get("target_id") or ""),
            "target_card_ref": str(confirmed.get("target_card_ref") or ""),
            "target_card_digest": str(confirmed.get("target_card_digest") or ""),
            "instruction": instruction,
            # The conversation card shows the operator's own words, so the run is
            # identifiable without opening the job record.
            "title": instruction[:120],
        },
    )
    get_runner(state_dir).submit(job)
    return {"session_id": session_id, "job_id": job.job_id, "reused": False}


def _handler_surface_scan(job: JobRecord, ctx: JobContext) -> Dict[str, Any]:
    """Surface discovery + autopilot only (no LLM loop)."""
    from agents.src_autopilot import SrcAutopilot
    from agents.surface_discovery import SurfaceScope

    state_dir = Path(ctx.job.payload.get("_state_dir") or ".")
    run_id = str(ctx.job.payload.get("run_id") or job.job_id)
    out_dir = state_dir / "src-agent-runs" / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    scope = SurfaceScope(program=f"console-{run_id}",
                         authorization=f"Console operator authorized scan of {job.target}",
                         allowed_domains=(), allowed_hosts=(), delay_seconds=0.5)
    ctx.emit("subtask_progress", phase="autopilot")
    autopilot = SrcAutopilot(scope, out_dir / "autopilot-state.json", out_dir,
                             max_rounds=3, max_candidates=100,
                             blackboard_path=out_dir / "src-blackboard.json")
    autopilot.run_round([job.target])
    return {"summary_ref": str(out_dir / "src-blackboard.json"), "progress": {"phase": "done"}}


def _handler_chat_turn(job: JobRecord, ctx: JobContext) -> Dict[str, Any]:
    """One conversation turn: route the intent, run chat, escalate if asked.

    Emits the unified event stream (user_message / mode_changed /
    subtask_started / assistant_message) so the turn renders inline alongside any
    subtask it launches.
    """
    from agents import src_chat
    from core import intent_router, modes, skills

    state_dir = Path(ctx.job.payload.get("_state_dir") or ".")
    session_id = job.session_id
    text = str(job.payload.get("text") or "")
    mode_name = str(job.payload.get("mode") or modes.DEFAULT_MODE)
    mode = modes.get_mode(mode_name)

    ctx.emit("user_message", text=text)
    decision = intent_router.route(text, mode=mode)

    if decision.mode and decision.mode != mode.name:
        mode = modes.get_mode(decision.mode)
        ctx.emit("mode_changed", mode=mode.name)

    if decision.escalates and decision.target:
        # Subtask node: a blackboard intent + a durable job (DAG/lease handled there).
        # The runner announces it (subtask_started) — don't emit a second copy here.
        run_id = f"SA-{int(time.time())}-{secrets.token_hex(3)}"
        subtask = get_registry(state_dir).create(
            session_id=session_id, turn_id=job.turn_id, kind=decision.subtask_kind,
            target=decision.target,
            payload={"run_id": run_id, "_state_dir": str(state_dir), "via": "intent_router",
                     "reason": decision.reason, "title": mode.title},
        )
        get_runner(state_dir).submit(subtask)

    prompt = skills.compose_prompt(mode.skill)
    if mode.system_fragment:
        prompt = (prompt + "\n\n" + mode.system_fragment).strip()
    session = src_chat._get_or_create_session(session_id, state_dir=state_dir)
    reply = src_chat.chat(session, text, system_prompt=prompt or None)
    ctx.emit("assistant_message", text=reply)
    return {"summary_ref": f"session:{session_id}", "progress": {"mode": mode.name,
                                                                "routed": decision.action}}


HANDLERS = {"src_loop": _handler_src_loop, "surface_scan": _handler_surface_scan,
            "chat_turn": _handler_chat_turn, TARGET_RUN_KIND: _handler_target_run}


# -- notify (best effort) ----------------------------------------------------
def _notify_hook() -> Optional[Callable[..., Any]]:
    if _NOTIFY_STATE["tried"]:
        return _NOTIFY_STATE["fn"]
    _NOTIFY_STATE["tried"] = True
    try:
        from notify.broadcaster import Broadcaster  # type: ignore
        _NOTIFY_STATE["fn"] = Broadcaster(audit_path=None)
    except Exception:  # noqa: BLE001 - notification is optional
        _NOTIFY_STATE["fn"] = None
    return _NOTIFY_STATE["fn"]


def _on_terminal(job_id: str, status: str) -> None:
    """Feishu notification when a job finishes while the operator is away."""
    broadcaster = _notify_hook()
    if broadcaster is None:
        return
    for entry in _ENTRIES.values():
        registry: JobRegistry = entry["registry"]
        job = registry.get(job_id)
        if job is None:
            continue
        elapsed = max(0.0, (job.finished_at or time.time()) - (job.started_at or job.created_at))
        label = {"completed": "finished", "failed": "failed", "interrupted": "interrupted"}.get(status, status)
        try:
            broadcaster.broadcast_task_terminal(
                job.target or job.job_id, task_id=job_id, status=label,
                elapsed=f"{int(elapsed)}s", report_ready=bool(job.summary_ref),
            )
        except Exception:  # noqa: BLE001
            pass
        return


# -- singletons --------------------------------------------------------------
def _entry(state_dir: Path | str) -> Dict[str, Any]:
    key = str(Path(state_dir).resolve())
    with _LOCK:
        entry = _ENTRIES.get(key)
        if entry is None:
            registry = JobRegistry(Path(state_dir) / "jobs")
            runner = JobRunner(
                registry=registry, handlers=HANDLERS,
                on_event=lambda sid, kind, payload: _emit(state_dir, sid, kind, payload),
                notify_fn=_on_terminal,
            )
            entry = {"registry": registry, "runner": runner}
            _ENTRIES[key] = entry
        return entry


def _emit(state_dir: Path | str, session_id: str, kind: str, payload: Dict[str, Any]) -> None:
    if not session_id:
        return
    try:
        get_log(state_dir, session_id).append(kind, session_id=session_id, **payload)
    except Exception:  # noqa: BLE001 - event sink must never fail a job
        pass


def get_registry(state_dir: Path | str) -> JobRegistry:
    return _entry(state_dir)["registry"]


def get_runner(state_dir: Path | str) -> JobRunner:
    return _entry(state_dir)["runner"]


def active_jobs(state_dir: Path | str, *, session_id: str = "") -> list:
    return [r for r in get_registry(state_dir).list(limit=0, active_only=True)
            if not session_id or r.session_id == session_id]


def recover(state_dir: Path | str, *, auto_resume: bool = False) -> list:
    """Mark jobs whose owning process died. Called at app start-up."""
    return get_registry(state_dir).recover(auto_resume=auto_resume)


def shutdown_all(*, wait: bool = False) -> None:
    with _LOCK:
        entries = list(_ENTRIES.values())
    for entry in entries:
        try:
            entry["runner"].shutdown(wait=wait)
        except Exception:  # noqa: BLE001
            pass


__all__ = [
    "HANDLERS", "TARGET_RUN_KIND", "active_jobs", "events_path", "get_log",
    "get_registry", "get_runner", "recover", "session_dir", "shutdown_all",
    "start_target_run", "ACTIVE",
]
