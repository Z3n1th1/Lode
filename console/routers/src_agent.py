"""Flask-style router builder: ``build(ctx) -> APIRouter``."""
from __future__ import annotations

import hmac
import ipaddress
import json
import math
import os
import re
import secrets
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import httpx
from fastapi import APIRouter, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

from core.file_lock import AdvisoryFileLock
from core.operation_profile import list_profiles
from core.src_blackboard import SrcBlackboard

try:
    from core import strix_conversation  # type: ignore
except Exception:  # noqa: BLE001
    strix_conversation = None  # type: ignore

try:
    from core import llm_settings  # type: ignore
except Exception:  # noqa: BLE001
    llm_settings = None  # type: ignore

try:
    from core import llm_pool  # type: ignore
except Exception:  # noqa: BLE001
    llm_pool = None  # type: ignore

from console import deps as _deps
from console.auth import _password_matches, _require_session
from console.models import (
    LlmSettingsRequest,
    LlmTestRequest,
    LoginRequest,
    ModelActiveRequest,
    ProjectIntakeRequest,
    SessionGuidanceRequest,
    SrcAgentChatRequest,
    SrcAgentStartRequest,
    SrcIntakeRequest,
    SrcSessionPatchRequest,
)
from console.projections import ReadOnlyControlPlane
from console.routers.base import _NOSTORE, Ctx
from console.deps import (
    ALLOWED_BLOCK_REASONS,
    ALLOWED_TASK_STATUSES,
    MAX_CARD_BYTES,
    MAX_STATE_EVENTS,
    MAX_STATE_FILE_BYTES,
    MAX_VISIBLE_ITEMS,
    MIN_PASSWORD_LENGTH,
    MIN_SESSION_SECRET_LENGTH,
    PROJECT_ID_RE,
    RUN_ID_RE,
    SESSION_ID_RE,
    TASK_ID_RE,
    INTAKE_SYSTEM,
    INTAKE_USER_TEMPLATE,
    INTAKE_TEXT_MAX,
    INTAKE_PROMPT_CHARS,
    INTAKE_BODY_MAX_BYTES,
    INTAKE_MAX_REDIRECTS,
    INTAKE_MAX_ITEMS,
    _bounded_profiles,
    _extract_scope,
    _fetch_public_page,
    _http_get_once,
    _normalize_domain,
    _normalize_domain_list,
    _normalize_scope,
    _normalize_url_list,
    _number,
    _sanitize_toggles,
    _text,
    _url_inside_scope,
    _valid_profile,
    _valid_public_target,
    _write_guidance,
    _write_intake,
)


def build(ctx: Ctx) -> APIRouter:
    router = APIRouter()

    # ---- SRC Agent background worker state ----
    _src_agent_state: Dict[str, Any] = {
        "status": "idle",  # idle | running | completed | failed
        "run_id": "",
        "target": "",
        "started_at": 0.0,
        "finished_at": 0.0,
        "summary": {},
        "error": "",
        "thread": None,
    }
    _src_agent_lock = threading.Lock()

    def _run_src_agent_background(target_url: str, authorization: str,
                                  allowed_domains: List[str], allowed_hosts: List[str],
                                  state_dir_path: Path,
                                  max_cycles: int, max_explore: int,
                                  reasoner_prefer: str, explorer_prefer: str) -> None:
        """Background thread: run autopilot → src_agent pipeline."""
        import traceback as _tb
        run_id = f"SA-{int(time.time())}-{secrets.token_hex(3)}"
        with _src_agent_lock:
            _src_agent_state["status"] = "running"
            _src_agent_state["run_id"] = run_id
            _src_agent_state["target"] = target_url
            _src_agent_state["started_at"] = time.time()
            _src_agent_state["finished_at"] = 0.0
            _src_agent_state["summary"] = {}
            _src_agent_state["error"] = ""

        out_dir = state_dir_path / "src-agent-runs" / run_id
        out_dir.mkdir(parents=True, exist_ok=True)
        bb_path = out_dir / "src-blackboard.json"

        try:
            from agents.surface_discovery import SurfaceScope
            from agents.src_autopilot import SrcAutopilot
            from agents.src_agent import run_src_agent

            parsed = urlparse(target_url)
            host = (parsed.hostname or "").lower()
            domains = [str(item).strip() for item in (allowed_domains or []) if str(item).strip()]
            hosts = [str(item).strip().lower() for item in (allowed_hosts or []) if str(item).strip()]
            if host and host not in domains and host not in hosts:
                # Auto-add the target's domain
                parts = host.split(".")
                if len(parts) >= 2:
                    domains.append(".".join(parts[-2:]))
                else:
                    domains.append(host)

            # 分层路由：显式参数优先，其次取设置文件投影的 env 默认（空了就按池故障转移）。
            reasoner = (reasoner_prefer or "").strip() or os.environ.get("SRC_REASONER_PREFER", "").strip()
            explorer = (explorer_prefer or "").strip() or os.environ.get("SRC_EXPLORER_PREFER", "").strip()

            scope = SurfaceScope(
                program=f"console-{run_id}",
                authorization=authorization or f"Console operator authorized scan of {target_url}",
                allowed_domains=tuple(domains),
                allowed_hosts=tuple(hosts),
                delay_seconds=0.5,
            )
            # 存档本轮的授权范围，便于复盘"当时到底授权了什么"。
            try:
                scope_doc = {
                    "schema": "SrcRunScope/v1",
                    "run_id": run_id,
                    "program": scope.program,
                    "authorization": scope.authorization,
                    "allowed_domains": domains,
                    "allowed_hosts": hosts,
                    "reasoner_prefer": reasoner,
                    "explorer_prefer": explorer,
                    "created_at": time.time(),
                }
                staged = out_dir / ".scope.json.tmp"
                staged.write_text(json.dumps(scope_doc, ensure_ascii=False, indent=2), encoding="utf-8")
                os.replace(staged, out_dir / "scope.json")
            except OSError:
                pass

            # Phase 1: Surface discovery + autopilot
            autopilot = SrcAutopilot(
                scope, out_dir / "autopilot-state.json", out_dir,
                max_rounds=3, max_candidates=100,
                blackboard_path=bb_path,
            )
            autopilot.run_round([target_url])

            # Phase 2: LLM agent loop
            summary = run_src_agent(
                bb_path, scope,
                max_cycles=max_cycles,
                max_explore_per_cycle=max_explore,
                reasoner_prefer=reasoner,
                explorer_prefer=explorer,
                worker_id=f"console-{run_id}",
            )

            with _src_agent_lock:
                _src_agent_state["status"] = "completed"
                _src_agent_state["finished_at"] = time.time()
                _src_agent_state["summary"] = summary
        except Exception as exc:
            with _src_agent_lock:
                _src_agent_state["status"] = "failed"
                _src_agent_state["finished_at"] = time.time()
                _src_agent_state["error"] = f"{exc.__class__.__name__}: {str(exc)[:300]}"

    @router.post("/api/v1/src-agent/start")
    def src_agent_start(payload: SrcAgentStartRequest, request: Request) -> JSONResponse:
        """Start the LLM-driven SRC agent pipeline in a background thread."""
        _require_session(request)
        target = _valid_public_target(payload.target_url)
        if not target:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_target")
        with _src_agent_lock:
            if _src_agent_state["status"] == "running":
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="agent_already_running")
        state_dir_path = Path(ctx.state_dir)
        t = threading.Thread(
            target=_run_src_agent_background,
            args=(target, payload.authorization, payload.allowed_domains, payload.allowed_hosts,
                  state_dir_path, payload.max_cycles, payload.max_explore,
                  payload.reasoner_prefer, payload.explorer_prefer),
            daemon=True,
        )
        t.start()
        with _src_agent_lock:
            _src_agent_state["thread"] = t
        return JSONResponse(content={"ok": True, "status": "started", "target": target}, headers=_NOSTORE)

    @router.get("/api/v1/src-agent/status")
    def src_agent_status(request: Request) -> JSONResponse:
        """Check the current SRC agent run status, including blackboard state."""
        _require_session(request)
        with _src_agent_lock:
            result = {k: v for k, v in _src_agent_state.items() if k != "thread"}
        # Append live blackboard snapshot if running
        if result.get("run_id"):
            bb_path = Path(ctx.state_dir) / "src-agent-runs" / result["run_id"] / "src-blackboard.json"
            if bb_path.is_file():
                try:
                    bb = SrcBlackboard(bb_path)
                    snap = bb.snapshot()
                    result["blackboard"] = {
                        "facts": len(snap.get("facts", [])),
                        "intents_queued": len([i for i in snap.get("intents", []) if i.get("status") == "queued"]),
                        "intents_completed": len([i for i in snap.get("intents", []) if i.get("status") == "completed"]),
                        "intents_dead_end": len([i for i in snap.get("intents", []) if i.get("status") == "dead_end"]),
                        "intents_blocked": len([i for i in snap.get("intents", []) if i.get("status") == "blocked"]),
                        "dead_ends": len(snap.get("dead_ends", [])),
                        "hints": len(snap.get("hints", [])),
                        "recent_hints": [
                            {"intent_id": h.get("intent_id"), "hint": h.get("hint", "")[:200], "source": h.get("source")}
                            for h in (snap.get("hints") or [])[-10:]
                        ],
                    }
                except Exception:
                    pass
        return JSONResponse(content=result, headers=_NOSTORE)

    @router.post("/api/v1/src-agent/stop")
    def src_agent_stop(request: Request) -> JSONResponse:
        """Request stop of the running SRC agent (best-effort)."""
        _require_session(request)
        with _src_agent_lock:
            if _src_agent_state["status"] != "running":
                return JSONResponse(content={"ok": False, "reason": "not_running"}, headers=_NOSTORE)
            _src_agent_state["status"] = "failed"
            _src_agent_state["error"] = "operator_stopped"
            _src_agent_state["finished_at"] = time.time()
        return JSONResponse(content={"ok": True, "status": "stopped"}, headers=_NOSTORE)

    # ---- SRC Agent interactive chat ----
    try:
        from agents.src_chat import (
            chat as _src_chat,
            _get_or_create_session as _src_get_session,
            list_sessions as _src_list_sessions,
            rename_session as _src_rename_session,
            set_session_pinned as _src_pin_session,
            delete_session as _src_delete_session,
            prune_empty_sessions as _src_prune_sessions,
        )
        _src_chat_available = True
    except Exception:
        _src_chat_available = False

    @router.get("/api/v1/src-agent/sessions")
    def src_agent_sessions(request: Request) -> JSONResponse:
        """List persisted SRC agent sessions (pinned first, then newest)."""
        _require_session(request)
        if not _src_chat_available:
            return JSONResponse(content={"sessions": [], "total": 0, "empty_count": 0}, headers=_NOSTORE)
        try:
            sessions = _src_list_sessions(Path(ctx.state_dir))
        except Exception:
            sessions = []
        return JSONResponse(content={
            "sessions": sessions,
            "total": len(sessions),
            "empty_count": len([s for s in sessions if s.get("empty")]),
        }, headers=_NOSTORE)

    @router.patch("/api/v1/src-agent/sessions/{session_id}")
    def src_agent_session_patch(session_id: str, payload: SrcSessionPatchRequest,
                                request: Request) -> JSONResponse:
        """Rename and/or pin a session."""
        _require_session(request)
        if not _src_chat_available:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail="src_chat_module_unavailable")
        result: Optional[Dict[str, Any]] = None
        if payload.pinned is not None:
            result = _src_pin_session(session_id, bool(payload.pinned), state_dir=Path(ctx.state_dir))
            if result is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="session_not_found")
        if payload.title.strip():
            result = _src_rename_session(session_id, payload.title, state_dir=Path(ctx.state_dir))
            if result is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="session_not_found")
        if result is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="nothing_to_update")
        return JSONResponse(content={"ok": True, **result}, headers=_NOSTORE)

    @router.delete("/api/v1/src-agent/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
    def src_agent_session_delete(session_id: str, request: Request) -> Response:
        """Delete one session workspace (transcript + blackboard + run artifacts)."""
        _require_session(request)
        if not _src_chat_available:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail="src_chat_module_unavailable")
        if not _src_delete_session(session_id, state_dir=Path(ctx.state_dir)):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="session_not_found")
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @router.post("/api/v1/src-agent/sessions/prune")
    def src_agent_sessions_prune(request: Request) -> JSONResponse:
        """Delete sessions with no conversation and no scan work."""
        _require_session(request)
        if not _src_chat_available:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail="src_chat_module_unavailable")
        return JSONResponse(content={"ok": True, **_src_prune_sessions(Path(ctx.state_dir))}, headers=_NOSTORE)

    @router.get("/api/v1/src-agent/history")
    def src_agent_history(request: Request, session_id: str = "") -> JSONResponse:
        """Get full message history of a session."""
        _require_session(request)
        if not _src_chat_available:
            return JSONResponse(content={"messages": []}, headers=_NOSTORE)
        if not session_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="missing_session_id")
        session = _src_get_session(session_id, state_dir=Path(ctx.state_dir))
        return JSONResponse(content={
            "session_id": session.session_id,
            "messages": session.messages,
            "events": session.events[-50:],
        }, headers=_NOSTORE)

    @router.post("/api/v1/src-agent/chat")
    def src_agent_chat(payload: SrcAgentChatRequest, request: Request) -> JSONResponse:
        """Interactive chat with the SRC agent. The agent can scan targets,
        analyze candidates, fetch URLs, and discuss findings with the operator."""
        _require_session(request)
        if not _src_chat_available:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail="src_chat_module_unavailable")
        message = _text(payload.message, limit=2000).strip()
        if not message:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="empty_message")
        session = _src_get_session(payload.session_id, state_dir=Path(ctx.state_dir))
        try:
            reply = _src_chat(session, message, timeout=120.0)
        except Exception as exc:
            reply = f"Error: {exc.__class__.__name__}: {str(exc)[:300]}"
        return JSONResponse(content={
            "session_id": session.session_id,
            "reply": reply,
            "events": session.events[-10:],
        }, headers=_NOSTORE)

    @router.get("/api/v1/src-agent/events")
    def src_agent_events(request: Request, session_id: str = "", since: float = 0) -> JSONResponse:
        """Get recent events from an SRC chat session (for real-time UI updates)."""
        _require_session(request)
        if not _src_chat_available or not session_id.strip():
            # No session id must NOT create one — that is how empty sessions appeared.
            return JSONResponse(content={"events": []}, headers=_NOSTORE)
        session = _src_get_session(session_id, state_dir=Path(ctx.state_dir))
        events = [e for e in session.events if e.get("ts", 0) > since]
        return JSONResponse(content={
            "session_id": session.session_id,
            "events": events[-50:],
        }, headers=_NOSTORE)

    @router.get("/api/v1/src-agent/progress")
    def src_agent_progress(request: Request, session_id: str = "") -> JSONResponse:
        """Full test progress summary: targets, findings, dead ends, timeline.

        If no session_id given, aggregates across ALL sessions on disk.
        """
        _require_session(request)
        if not _src_chat_available:
            return JSONResponse(content={"error": "unavailable"}, headers=_NOSTORE)

        if session_id:
            session = _src_get_session(session_id, state_dir=Path(ctx.state_dir))
            if session.test_log:
                return JSONResponse(content=session.test_log.summary(), headers=_NOSTORE)
            return JSONResponse(content={"error": "no_test_log"}, headers=_NOSTORE)

        # Aggregate across all sessions
        from core.test_log import SrcTestLog
        chat_dir = Path(ctx.state_dir) / "src-chat"
        agg = {
            "schema": "SrcTestSummary/v1",
            "scope": "all-sessions",
            "sessions": 0,
            "totals": {"targets": 0, "scans": 0, "urls_explored": 0,
                       "total_explores": 0, "findings": 0, "dead_ends": 0, "errors": 0},
            "findings": [],
            "targets": {},
        }
        if chat_dir.is_dir():
            for sess_dir in chat_dir.iterdir():
                if not sess_dir.is_dir():
                    continue
                log_path = sess_dir / "src-test-log.jsonl"
                if not log_path.is_file():
                    continue
                agg["sessions"] += 1
                try:
                    sub = SrcTestLog(sess_dir).summary()
                    for k, v in sub.get("totals", {}).items():
                        agg["totals"][k] = agg["totals"].get(k, 0) + (v if isinstance(v, int) else 0)
                    agg["findings"].extend(sub.get("findings", []))
                    for t, info in (sub.get("targets") or {}).items():
                        agg["targets"][t] = info
                except Exception:
                    continue
        agg["findings"] = agg["findings"][-50:]
        return JSONResponse(content=agg, headers=_NOSTORE)

    return router
