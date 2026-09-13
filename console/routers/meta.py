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
    LoginRequest,
)
from console.projections import ReadOnlyControlPlane
from console.routers.base import _NOSTORE, Ctx



def build(ctx: Ctx) -> APIRouter:
    router = APIRouter()

    @router.get("/healthz")
    def healthz() -> Dict[str, str]:
        return {"status": "ok", "authentication": "required"}

    @router.post("/api/v1/session", status_code=status.HTTP_204_NO_CONTENT)
    def login(payload: LoginRequest, request: Request) -> Response:
        if not _password_matches(payload.password, ctx.password):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_credentials")
        request.session.clear()
        request.session["control_plane_authenticated"] = True
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @router.delete("/api/v1/session", status_code=status.HTTP_204_NO_CONTENT)
    def logout(request: Request) -> Response:
        request.session.clear()
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @router.get("/api/v1/dashboard")
    def dashboard(request: Request) -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=ctx.control_plane.snapshot(), headers={"Cache-Control": "no-store"})

    @router.get("/api/v1/src-autopilot")
    def src_autopilot(request: Request) -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=ctx.control_plane.src_autopilot(), headers=_NOSTORE)

    return router
