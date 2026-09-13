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

    @router.get("/api/v1/proxy")
    def proxy(request: Request) -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=ctx.control_plane.proxy(), headers=_NOSTORE)

    @router.get("/api/v1/report")
    def report(request: Request, task_id: str = "") -> Response:
        _require_session(request)
        return Response(content=ctx.control_plane.report(task_id), media_type="text/plain; charset=utf-8",
                        headers=_NOSTORE)

    @router.get("/api/v1/profiles")
    def profiles(request: Request) -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=ctx.control_plane.profiles_detail(), headers=_NOSTORE)

    @router.get("/api/v1/task")
    def task(request: Request, id: str = "") -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=ctx.control_plane.task_detail(id), headers=_NOSTORE)

    @router.get("/api/v1/projects")
    def projects(request: Request) -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=ctx.control_plane.projects(), headers=_NOSTORE)

    @router.get("/api/v1/project")
    def project(request: Request, id: str = "") -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=ctx.control_plane.project_detail(id), headers=_NOSTORE)

    @router.get("/api/v1/trajectory")
    def trajectory(request: Request, id: str = "") -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=ctx.control_plane.session_trajectory(id), headers=_NOSTORE)

    @router.post("/api/v1/session/guidance")
    def session_guidance(payload: SessionGuidanceRequest, request: Request) -> JSONResponse:
        """P5-e 受控写:对某会话追加"继续深挖"指导。console 直发=直接进处理队列;
        飞书侧只收提醒通知(不带审批要求)。若 agent 侧判定触发人工门,审批按钮在 console 就地支出。"""
        _require_session(request)
        if not SESSION_ID_RE.fullmatch(str(payload.session_id or "")):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_session_id")
        target = _valid_public_target(payload.target)
        if not target:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_target")
        guidance = _text(payload.guidance, limit=1000).strip()
        if not guidance:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="empty_guidance")
        gid = f"SG-{int(time.time())}-{secrets.token_hex(3)}"
        rec = {"schema": "SessionGuidanceRequest/v1", "id": gid,
               "session_id": _text(payload.session_id, limit=128), "target": target,
               "guidance": guidance, "status": "pending_review", "origin": "console",
               "created_at": time.time(), "created_by": "control_plane"}
        try:
            _write_guidance(ctx.control_plane.state_dir, rec)
        except OSError:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="write_failed")
        return JSONResponse(content={"ok": True, "id": gid, "status": "pending_review",
                                     "note": "已提交(console 直发,排队处理;若触发人工门会在本页就地支审批按钮)"},
                            headers=_NOSTORE)

    @router.get("/api/v1/session/guidance")
    def session_guidance_list(request: Request, id: str = "") -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=ctx.control_plane.session_guidance_list(id), headers=_NOSTORE)

    @router.post("/api/v1/project/intake")
    def project_intake(payload: ProjectIntakeRequest, request: Request) -> JSONResponse:
        """P5-b 唯一受控写:校验后落 intake 请求文件。**不执行**——agent 侧消费时走 TargetCard 确认门。"""
        _require_session(request)
        target = _valid_public_target(payload.target_url)
        if not target:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_target")
        profile = _valid_profile(payload.engagement_profile)
        if not profile:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_profile")
        iid = f"PI-{int(time.time())}-{secrets.token_hex(3)}"
        rec = {
            "schema": "ProjectIntakeRequest/v1", "intake_id": iid, "target_url": target,
            "name": _text(payload.name, limit=120) or target, "engagement_profile": profile,
            "toggles": _sanitize_toggles(payload.toggles), "status": "pending_review",
            "created_at": time.time(), "created_by": "control_plane",
        }
        try:
            _write_intake(ctx.control_plane.state_dir, rec)
        except OSError:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="intake_write_failed")
        return JSONResponse(content={
            "ok": True, "intake_id": iid, "status": "pending_review",
            "note": "已提交(console 直发,排队处理;飞书仅收提醒通知,无审批要求)",
        }, headers=_NOSTORE)

    @router.get("/api/v1/project/intakes")
    def project_intakes(request: Request) -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=ctx.control_plane.project_intakes(), headers=_NOSTORE)

    @router.get("/api/v1/project/results")
    def project_results(request: Request, id: str = "") -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=ctx.control_plane.project_results(id), headers=_NOSTORE)

    return router
