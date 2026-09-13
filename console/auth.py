"""Console session authentication (shared admin password)."""

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



def _require_session(request: Request) -> None:
    if request.session.get("control_plane_authenticated") is not True:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication_required")


def _password_matches(submitted: str, expected: str) -> bool:
    """Compare UTF-8 password bytes without leaking where they differ."""
    return hmac.compare_digest(submitted.encode("utf-8"), expected.encode("utf-8"))
