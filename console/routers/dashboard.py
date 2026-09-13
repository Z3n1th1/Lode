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

    @router.get("/api/v1/findings")
    def findings(request: Request) -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=ctx.control_plane.findings(), headers=_NOSTORE)

    @router.get("/api/v1/system")
    def system(request: Request) -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=ctx.control_plane.system(), headers=_NOSTORE)

    @router.get("/api/v1/models")
    def models(request: Request) -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=ctx.control_plane.models(), headers=_NOSTORE)

    @router.post("/api/v1/model/active")
    def model_active(payload: ModelActiveRequest, request: Request) -> JSONResponse:
        """R2: 切换活跃 LLM provider(写运行时状态文件;core.llm_pool 下次调用即生效,无需重启)。"""
        _require_session(request)
        result = ctx.control_plane.set_active_model(str(payload.name or ""))
        if not result.get("ok"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail=str(result.get("error", "invalid")))
        return JSONResponse(content=result, headers=_NOSTORE)

    return router
