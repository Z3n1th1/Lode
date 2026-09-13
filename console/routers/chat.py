"""Unified conversation stream: one SSE stream per chat session.

Chat turns and launched subtasks both write the session's append-only event log
(``src-chat/<id>/events.jsonl``), so this endpoint is a thin tail: the client
reconnects with ``since=<last seq>`` and never misses an event.
"""
from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import StreamingResponse

from console.auth import _require_session
from console.deps import SESSION_ID_RE
from console.routers.base import Ctx

POLL_SECONDS = 1.0
KEEPALIVE_EVERY = 15          # ~15s of silence -> a comment frame
MAX_IDLE_SECONDS = 3600       # give up on a dead client after an hour


def build(ctx: Ctx) -> APIRouter:
    router = APIRouter()

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
