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
)
from console.projections import ReadOnlyControlPlane
from console.routers.base import _NOSTORE, Ctx
from console.deps import (
    _text,
)


def build(ctx: Ctx) -> APIRouter:
    router = APIRouter()

    # ---- LLM 供应商设置（界面配 key + 分层模型）。响应只回掩码，绝不回 api_key。----

    @router.get("/api/v1/llm/settings")
    def llm_settings_read(request: Request) -> JSONResponse:
        _require_session(request)
        if llm_settings is None:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail="llm_settings_unavailable")
        path = llm_settings.settings_path(ctx.state_dir)
        content = llm_settings.mask_settings(llm_settings.read_settings(path))
        content["effective"] = {
            "providers_env_override": bool(os.environ.get("LLM_PROVIDERS", "").strip()),
            "legacy_env_override": bool(os.environ.get("LLM_API_KEY", "").strip()),
            "reasoner_prefer": os.environ.get("SRC_REASONER_PREFER", ""),
            "explorer_prefer": os.environ.get("SRC_EXPLORER_PREFER", ""),
        }
        content["settings_path"] = str(path)
        return JSONResponse(content=content, headers=_NOSTORE)

    @router.put("/api/v1/llm/settings")
    def llm_settings_write(payload: LlmSettingsRequest, request: Request) -> JSONResponse:
        _require_session(request)
        if llm_settings is None:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail="llm_settings_unavailable")
        path = llm_settings.settings_path(ctx.state_dir)
        stored = llm_settings.read_settings(path)
        try:
            doc = llm_settings.write_settings(
                [p.model_dump() for p in payload.providers],
                payload.tiers,
                path=path,
                stored=stored,
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail=f"invalid_settings:{str(exc)[:200]}")
        # 写盘后立即投影到 env，本轮起的 SRC run 就用新配置（无需重启 Console）。
        applied = llm_settings.apply_to_environ(doc, state_dir=Path(ctx.state_dir), force=True)
        content = llm_settings.mask_settings(doc)
        content["ok"] = True
        content["applied_env"] = applied
        return JSONResponse(content=content, headers=_NOSTORE)

    @router.post("/api/v1/llm/test")
    def llm_provider_test(payload: LlmTestRequest, request: Request) -> JSONResponse:
        """Probe provider connectivity. A failure is 200 + ok=false, not a 5xx."""
        _require_session(request)
        if llm_pool is None:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail="llm_pool_unavailable")
        if payload.provider is not None:
            provider = payload.provider.model_dump()
            if not str(provider.get("api_key") or "").strip() and llm_settings is not None:
                # A keyless draft row: fall back to the stored key of the same name.
                stored = llm_settings.read_settings(llm_settings.settings_path(ctx.state_dir))
                keep = next((p for p in stored["providers"] if p["name"] == provider["name"]), None)
                if keep:
                    provider["api_key"] = keep.get("api_key", "")
        else:
            name = _text(payload.name, limit=64)
            if not name:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="name_required")
            provider = next((p for p in llm_pool.parse_providers() if p.get("name") == name), None)
            if provider is None and llm_settings is not None:
                stored = llm_settings.read_settings(llm_settings.settings_path(ctx.state_dir))
                provider = next((p for p in stored["providers"] if p["name"] == name), None)
            if provider is None:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="provider_not_found")
        if not str(provider.get("api_key") or "").strip():
            return JSONResponse(content={"ok": False, "name": provider.get("name", ""),
                                         "model": provider.get("model", ""), "latency_ms": 0,
                                         "error": "missing_base_url_or_api_key"}, headers=_NOSTORE)
        return JSONResponse(content=llm_pool.probe_provider(provider), headers=_NOSTORE)

    return router
