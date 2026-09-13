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

    # ---- H1 接入：粘贴整页 / 给 URL → LLM 抽 scope（只抽取，不开跑；开跑走 /src-agent/start）----

    @router.post("/api/v1/src-agent/intake")
    def src_intake(payload: SrcIntakeRequest, request: Request) -> JSONResponse:
        _require_session(request)
        warnings: List[str] = []
        text = _text(payload.text, limit=INTAKE_TEXT_MAX).replace("\x00", "")
        url = _text(payload.url, limit=300)
        if text and url:
            warnings.append("both_text_and_url_text_wins")
        source = "pasted_text"
        content = text
        if not content and url:
            fetched = _fetch_public_page(url)
            if not fetched["ok"]:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                    detail=fetched["error"] or "fetch_failed")
            content = fetched["text"]
            source = fetched["url"]
        if not content.strip():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="empty_intake")
        if len(content) > INTAKE_PROMPT_CHARS:
            warnings.append(f"truncated_to_{INTAKE_PROMPT_CHARS}_chars")
        result = _extract_scope(content, source=source)
        if not result["ok"]:
            unavailable = result["error"] in ("llm_unavailable", "llm_pool_unavailable")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE if unavailable else status.HTTP_502_BAD_GATEWAY,
                detail=result["error"],
            )
        extracted = result["extracted"]
        record_id = f"LI-{int(time.time())}-{secrets.token_hex(3)}"
        out_dir = Path(ctx.state_dir) / "llm-intake"
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
            doc = {"schema": "LlmIntake/v1", "id": record_id, "source": source[:300],
                   "created_at": time.time(), "extracted": extracted}
            staged = out_dir / f".{record_id}.tmp"
            staged.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
            os.replace(staged, out_dir / f"{record_id}.json")
        except OSError:
            warnings.append("audit_write_failed")
        return JSONResponse(content={"ok": True, "id": record_id, "source": source[:300],
                                     "extracted": extracted, "warnings": warnings}, headers=_NOSTORE)

    return router
