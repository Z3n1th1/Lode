"""Unified conversation: modes, turns and the SSE event stream.

Chat turns and launched subtasks both write the session's append-only event log
(``src-chat/<id>/events.jsonl``), so the stream endpoint is a thin tail: the
client reconnects with ``since=<last seq>`` and never misses an event. A turn is
accepted with 202 and executed as a durable job — never on the request thread.
"""
from __future__ import annotations

import asyncio
import json
import secrets
import time

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

from console.auth import _require_session
from console.deps import SESSION_ID_RE, _text
from console.routers.base import Ctx, _NOSTORE

POLL_SECONDS = 1.0
KEEPALIVE_EVERY = 15          # ~15s of silence -> a comment frame
MAX_IDLE_SECONDS = 3600       # give up on a dead client after an hour


class ChatMessageRequest(BaseModel):
    text: str
    mode: str = ""


class NewSessionRequest(BaseModel):
    mode: str = ""


def build(ctx: Ctx) -> APIRouter:
    router = APIRouter()

    @router.get("/api/v1/modes")
    def list_modes(request: Request) -> JSONResponse:
        """Available conversation modes (skill + tier + autonomy + tools)."""
        _require_session(request)
        from core import modes

        return JSONResponse(content={"modes": modes.list_modes(),
                                     "default": modes.DEFAULT_MODE}, headers=_NOSTORE)

    @router.post("/api/v1/chat/sessions")
    def new_session(payload: NewSessionRequest, request: Request) -> JSONResponse:
        """Mint a session id. Nothing is written until the first turn."""
        _require_session(request)
        from core import modes

        mode = modes.get_mode(payload.mode).name
        session_id = "src-" + secrets.token_hex(6)
        return JSONResponse(content={"session_id": session_id, "mode": mode}, headers=_NOSTORE)

    @router.get("/api/v1/chat/sessions/{session_id}/events")
    def session_events(session_id: str, request: Request, since: int = 0, limit: int = 500) -> JSONResponse:
        """Replay events (for the initial render before the SSE stream attaches)."""
        _require_session(request)
        if not SESSION_ID_RE.fullmatch(session_id or ""):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_session_id")
        from console import jobs as _jobs

        log = _jobs.get_log(ctx.state_dir, session_id)
        events = log.since(int(since), limit=max(1, min(2000, int(limit))))
        return JSONResponse(content={"events": events, "max_seq": log.max_seq()}, headers=_NOSTORE)

    @router.post("/api/v1/chat/sessions/{session_id}/messages", status_code=status.HTTP_202_ACCEPTED)
    def post_message(session_id: str, payload: ChatMessageRequest, request: Request) -> JSONResponse:
        """Accept a turn and run it as a durable job (202 + turn_id)."""
        _require_session(request)
        if not SESSION_ID_RE.fullmatch(session_id or ""):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_session_id")
        text = _text(payload.text, limit=8000).strip()
        if not text:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="empty_message")

        from console import jobs as _jobs
        from core import modes

        runner = _jobs.get_runner(ctx.state_dir)
        if _jobs.active_jobs(ctx.state_dir, session_id=session_id):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="turn_already_running")
        turn_id = "T-" + secrets.token_hex(4)
        job = _jobs.get_registry(ctx.state_dir).create(
            session_id=session_id, turn_id=turn_id, kind="chat_turn",
            payload={"text": text, "mode": modes.get_mode(payload.mode or "").name,
                     "_state_dir": str(ctx.state_dir)},
        )
        runner.submit(job)
        return JSONResponse(
            content={"session_id": session_id, "turn_id": turn_id, "job_id": job.job_id},
            status_code=status.HTTP_202_ACCEPTED, headers=_NOSTORE,
        )

    @router.post("/api/v1/chat/sessions/{session_id}/turn/stop")
    def stop_turn(session_id: str, request: Request) -> JSONResponse:
        """Cooperatively stop the session's running turn/subtasks."""
        _require_session(request)
        if not SESSION_ID_RE.fullmatch(session_id or ""):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_session_id")
        from console import jobs as _jobs

        active = _jobs.active_jobs(ctx.state_dir, session_id=session_id)
        if not active:
            return JSONResponse(content={"ok": False, "reason": "not_running"}, headers=_NOSTORE)
        runner = _jobs.get_runner(ctx.state_dir)
        for job in active:
            runner.stop(job.job_id)
        return JSONResponse(content={"ok": True, "job_ids": [j.job_id for j in active]},
                            headers=_NOSTORE)

    @router.get("/api/v1/chat/sessions/{session_id}/stream")
    async def chat_stream(session_id: str, request: Request, since: int = 0) -> StreamingResponse:
        """Tail one session's event log as ``text/event-stream``."""
        _require_session(request)
        if not SESSION_ID_RE.fullmatch(session_id or ""):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_session_id")

        from console import jobs as _jobs

        log = _jobs.get_log(ctx.state_dir, session_id)
        cursor = max(0, int(since))

        async def gen():
            nonlocal cursor
            idle = 0
            while idle < MAX_IDLE_SECONDS:
                if await request.is_disconnected():
                    break
                events = log.since(cursor, limit=200)
                if events:
                    idle = 0
                    for event in events:
                        cursor = max(cursor, int(event.get("seq") or cursor))
                        yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
                else:
                    idle += int(POLL_SECONDS)
                    if idle % KEEPALIVE_EVERY < POLL_SECONDS:
                        yield ": keep-alive\n\n"
                await asyncio.sleep(POLL_SECONDS)

        return StreamingResponse(
            gen(), media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )

    return router
