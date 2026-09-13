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



try:                                   # F1 对话台芯:读 Strix agents.db 真实多智能体对话
    from core import strix_conversation  # type: ignore
except Exception:                      # noqa: BLE001
    strix_conversation = None          # type: ignore

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
    target_url: str
    name: str = ""
    engagement_profile: str = ""
    toggles: Dict[str, Any] = {}


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
    model: str = "deepseek-chat"
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


class SrcIntakeRequest(BaseModel):
    """Read a HackerOne program page (URL) or pasted text into a scope draft."""
    url: str = ""
    text: str = ""


class SrcAgentStartRequest(BaseModel):
    """Request to start an LLM-driven SRC agent run against a target."""
    target_url: str
    session_id: str = ""          # when set, job events stream into that chat session
    authorization: str = ""
    allowed_domains: List[str] = []
    allowed_hosts: List[str] = []
    max_cycles: int = 20
    max_explore: int = 3
    reasoner_prefer: str = ""
    explorer_prefer: str = ""


class SrcAgentChatRequest(BaseModel):
    """Send a message to the SRC agent chat."""
    message: str
    session_id: str = ""


class SrcSessionPatchRequest(BaseModel):
    """Rename and/or pin a stored session."""
    title: str = ""
    pinned: Optional[bool] = None
