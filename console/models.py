"""Pydantic request bodies for the Console API."""

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
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

from core.file_lock import AdvisoryFileLock
from core.operation_profile import list_profiles
from core.src_blackboard import SrcBlackboard


try:                                   # LLM 供应商设置(界面配置 key/分层模型)
    from core import llm_settings      # type: ignore
except Exception:                      # noqa: BLE001
    llm_settings = None                # type: ignore

try:                                   # LLM provider 池(连通性测试 + 分层路由)
    from core import llm_pool          # type: ignore
except Exception:                      # noqa: BLE001
    llm_pool = None                    # type: ignore


class LoginRequest(BaseModel):
    password: str


class ProjectIntakeRequest(BaseModel):
    """Step 1 of the intake gate: what the operator wants, before anything is bound.

    ``toggles`` is the raw dialog state; the server normalizes it onto the gate's
    options contract and refuses the switches it cannot honour.
    """

    target_url: str
    instruction: str = ""
    engagement_profile: str = ""
    toggles: Dict[str, Any] = {}


class ProjectIntakeConfirmRequest(BaseModel):
    """Step 2: echo the preview binding back, unchanged.

    ``session_id`` picks the conversation the run should stream into; empty means
    the server mints one and returns it.  ``run`` can be turned off for a caller
    that only wants the card.
    """

    intake_id: str
    options_digest: str
    session_id: str = ""
    run: bool = True


class SessionGuidanceRequest(BaseModel):
    session_id: str
    target: str
    guidance: str


class ModelActiveRequest(BaseModel):
    name: str


class LlmProviderInput(BaseModel):
    """One provider row submitted from the settings panel.

    ``api_key`` is empty when the UI round-trips an already-saved provider (the
    API never returns keys); the stored key is then carried over by name unless
    ``clear_key`` is set.
    """
    name: str
    base_url: str = "https://api.deepseek.com"
    model: str = "deepseek-flash"
    api_key: str = ""
    clear_key: bool = False


class LlmSettingsRequest(BaseModel):
    providers: List[LlmProviderInput] = []
    # role -> provider name substring ("" = let the pool fail over)
    tiers: Dict[str, str] = {}


class LlmTestRequest(BaseModel):
    """Test connectivity for a stored provider or an unsaved draft row."""
    name: str = ""
    provider: LlmProviderInput | None = None
