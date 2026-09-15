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
from typing import Any, Callable, Dict, List, Optional

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

    unimplemented = ""
    if decision.escalates and decision.target:
        if decision.subtask_kind not in HANDLERS:
            # The router proposes a kind nothing can run — an existing kind whose
            # executor was pulled, or (more often) one the LLM classifier invented.
            # Launching it would only mint a job that fails ``no_handler:<kind>``,
            # so the turn says so in the conversation instead.
            unimplemented = (f"（未启动后台任务:{decision.subtask_kind} 还没有执行器,"
                             f"本轮只在对话里分析。）")
        else:
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
    # ``mode.tools`` is what the model may call inline *in this turn* -- a different
    # axis from ``HANDLERS`` above, which is which background executors exist. They
    # are deliberately independent: a kind can be declared in ``SUBTASK_FOR_MODE``
    # with no executor, and a mode can carry inline tools with no executor at all.
    reply = src_chat.chat(session, text, system_prompt=prompt or None,
                          tool_names=mode.tools, fallback_prompt=mode.system_fragment or None)
    ctx.emit("assistant_message", text=f"{unimplemented}\n\n{reply}" if unimplemented else reply)
    return {"summary_ref": f"session:{session_id}", "progress": {"mode": mode.name,
                                                                "routed": decision.action}}


HANDLERS = {"src_loop": _handler_src_loop, "surface_scan": _handler_surface_scan,
            "chat_turn": _handler_chat_turn, TARGET_RUN_KIND: _handler_target_run}


# -- report back into the conversation ---------------------------------------
# A run that ends silently is the worst outcome: the operator launched it from
# the conversation, so the conversation is where its answer belongs.  The runner
# already emits subtask_finished, but that is a machine event — this turns the
# run's own blackboard into one assistant message so the turn is actually closed.
#
# The blackboard holds findings as *hints* (see SrcAgentLoop._process_explorer_result):
# high confidence marks the intent blocked for human review, medium completes it.
#
# Every handler that leaves a blackboard behind, i.e. every one but ``chat_turn`` —
# that turn already emits its own assistant_message, and reporting on it would just
# echo the reply back.  Derived from HANDLERS so a new run kind cannot be forgotten.
RUN_KINDS = frozenset(HANDLERS) - {"chat_turn"}

REPORT_SYSTEM = """\
你是 SRC 挖洞的执行总结者。只根据给定材料说话:不要推测,不要补充材料里没有的漏洞。
中文,三句以内,直接给结论——发现了什么、置信度如何、下一步建议做什么。
材料里没有发现就直说没有发现。不要复述任务数量,不要客套话。"""

_REPORT_STATE: Dict[str, Any] = {"tried": False, "fn": None}


def _report_llm() -> Optional[Callable[[str, str], Optional[str]]]:
    """The completion seam for the report; ``None`` when no transport is available."""
    if _REPORT_STATE["tried"]:
        return _REPORT_STATE["fn"]
    _REPORT_STATE["tried"] = True
    try:
        from core.llm_client import complete_messages
    except Exception:  # noqa: BLE001 - a report is optional
        _REPORT_STATE["fn"] = None
        return None

    def _complete(system: str, user: str) -> Optional[str]:
        try:
            message = complete_messages(
                [{"role": "system", "content": system}, {"role": "user", "content": user}],
                timeout=60.0, max_tokens=800, temperature=0.2,
            )
        except Exception:  # noqa: BLE001 - a report must never fail a job
            return None
        if not message:
            return None
        return str(message.get("content") or "").strip() or None

    _REPORT_STATE["fn"] = _complete
    return _complete


def _blackboard_digest(doc: Dict[str, Any]) -> str:
    """Compact, factual digest of a finished run. Facts only, no interpretation."""
    workmem = doc.get("workmem") if isinstance(doc.get("workmem"), dict) else {}
    intents = [i for i in (doc.get("intents") or []) if isinstance(i, dict)]
    hints = [h for h in (doc.get("hints") or []) if isinstance(h, dict)]
    dead_ends = [d for d in (doc.get("dead_ends") or []) if isinstance(d, dict)]

    def count(status: str) -> int:
        return sum(1 for i in intents if str(i.get("status") or "") == status)

    lines: List[str] = []
    goal = str(workmem.get("goal") or "").strip()
    if goal:
        lines.append(f"目标:{goal}")
    lines.append(
        f"任务 {len(intents)} 个:完成 {count('completed')}、"
        f"待人工复核 {count('blocked')}、死路 {len(dead_ends)}"
    )
    if hints:
        lines.append("发现(explorer 给出,未经验证):")
        for h in hints[-12:]:
            lines.append(f"- {str(h.get('hint') or '')[:300]}")
    else:
        lines.append("发现:无")
    focus = str(workmem.get("focus") or "").strip()
    if focus:
        lines.append(f"最后的推理焦点:{focus[:300]}")
    return "\n".join(lines)


def _report_back(state_dir: Path | str, job: JobRecord) -> None:
    """Close the loop: turn a finished run's blackboard into one assistant message."""
    if job.kind not in RUN_KINDS or not job.summary_ref:
        return
    try:
        doc = json.loads(Path(job.summary_ref).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    if not isinstance(doc, dict):
        return
    complete = _report_llm()
    if complete is None:
        return
    text = complete(REPORT_SYSTEM, _blackboard_digest(doc))
    if not text:
        # No model, or it produced nothing: stay silent. A canned line would be
        # noise dressed up as analysis.
        return
    _emit(state_dir, job.session_id, "assistant_message", {"text": text, "job_id": job.job_id})


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
    """A job reached a terminal state: close the loop, then notify.

    The two steps are independent on purpose — the Feishu hook used to return
    early when no broadcaster could be imported, which would have swallowed the
    report for every installation without one.
    """
    state_dir = ""
    job: Optional[JobRecord] = None
    for key, entry in _ENTRIES.items():
        found = entry["registry"].get(job_id)
        if found is not None:
            state_dir, job = key, found
            break
    if job is None:
        return
    # Only a completed run has a blackboard worth summarising; a failed one is
    # already visible as a failed subtask row and its error text is internal.
    if status == "completed":
        _report_back(state_dir, job)
    _notify_terminal(job, status)


def _notify_terminal(job: JobRecord, status: str) -> None:
    """Feishu notification when a job finishes while the operator is away."""
    broadcaster = _notify_hook()
    if broadcaster is None:
        return
    elapsed = max(0.0, (job.finished_at or time.time()) - (job.started_at or job.created_at))
    label = {"completed": "finished", "failed": "failed", "interrupted": "interrupted"}.get(status, status)
    try:
        broadcaster.broadcast_task_terminal(
            job.target or job.job_id, task_id=job.job_id, status=label,
            elapsed=f"{int(elapsed)}s", report_ready=bool(job.summary_ref),
        )
    except Exception:  # noqa: BLE001
        pass


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
