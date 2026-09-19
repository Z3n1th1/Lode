"""Control-plane constants and validation helpers.

Extracted from the old control_plane monolith: request parsing guards,
the public-target (SSRF) gate, scope normalisation and intake plumbing."""

import hmac
import json
import math
import re
import secrets
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import httpx
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

from core.file_lock import AdvisoryFileLock, replace_with_retry
from core.operation_profile import list_profiles
from core.src_blackboard import SrcBlackboard
from core.targets import public_target_reason


try:                                   # LLM 供应商设置(界面配置 key/分层模型)
    from core import llm_settings      # type: ignore
except Exception:                      # noqa: BLE001
    llm_settings = None                # type: ignore

try:                                   # LLM provider 池(连通性测试 + 分层路由)
    from core import llm_pool          # type: ignore
except Exception:                      # noqa: BLE001
    llm_pool = None                    # type: ignore


MAX_STATE_FILE_BYTES = 2 * 1024 * 1024
MAX_STATE_EVENTS = 2_000
MAX_VISIBLE_ITEMS = 20
# 项目列表是分页的,一页最多给这么多。20 这个默认值继续用 MAX_VISIBLE_ITEMS;
# 上限另外给,免得一个 limit 参数就能把整本台账拉进响应体。
MAX_PROJECT_PAGE = 200
MAX_CARD_BYTES = 128 * 1024
MIN_PASSWORD_LENGTH = 16
MIN_SESSION_SECRET_LENGTH = 32
TASK_ID_RE = re.compile(r"T-[0-9]+$")
RUN_ID_RE = re.compile(r"[A-Za-z0-9_.-]{1,128}$")
PROJECT_ID_RE = re.compile(r"[A-Za-z0-9_.-]{1,120}$")   # P5 项目 id = target 派生 slug
SESSION_ID_RE = re.compile(r"[A-Za-z0-9_.:-]{1,128}$")  # P5 会话 id = goal_id;禁 / 与 .. 防穿越
ALLOWED_TASK_STATUSES = frozenset(
    {"reserved", "running", "recovery_pending", "interrupted", "finished", "failed", "timeout", "blocked"}
)
ALLOWED_BLOCK_REASONS = frozenset(
    {
        "external_tool_runner_unconfigured",
        "synthetic_no_execution",
        "backend_capability_unavailable",
        "runner_blocked",
        "tool_runner_blocked",
    }
)


def _text(value: Any, *, limit: int = 256) -> str:
    if not isinstance(value, str):
        return ""
    return value[:limit]


def _number(value: Any, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return default
    try:
        number = float(value)
        return number if math.isfinite(number) else default
    except (TypeError, ValueError):
        return default


def _bounded_profiles(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    profiles = []
    for item in value[:8]:
        profile = _text(item, limit=80)
        if profile:
            profiles.append(profile)
    return profiles


# ---- P5-b 新建项目 intake(唯一受控写:只落"请求文件"+严格校验,绝不执行;执行仍走 agent 侧确认门) ----
_INTAKE_TOGGLE_KEYS = frozenset({
    "scan_enabled", "fingerprint_precise", "nuclei", "tscan",
    "asset_inventory", "subdomain_enum", "intel", "poc_research",
    "proxy_route", "network_gate", "edge_human_gate",
})
_INTAKE_BRUTE_FLAGS = frozenset({"enabled", "path", "port", "password", "username", "sms", "subdomain"})


def _valid_public_target(raw: str) -> str:
    """校验目标为 http(s)/公网域名;拒私网/回环/链路本地/元数据/保留地址(防越权+SSRF 面)。返回归一化目标或空。

    判定本身在 ``core.targets.public_target_reason`` —— 对话和建卡两条路必须用同一个
    闸门,所以这里只保留调用方习惯的"通过则返回原串,否则空串"这个形状。
    """
    s = (raw or "").strip()
    if public_target_reason(s):
        return ""
    return s[:300]




def _valid_profile(pid: str) -> str:
    valid = set()
    for key, prof in list_profiles().items():
        valid.add(key)
        for alias in (prof.get("aliases") or []):
            valid.add(str(alias))
    p = _text(pid, limit=80)
    return p if p in valid else ""


def _brute_requested(raw: Any) -> bool:
    """True when the browser asked for any brute-force capability.

    Read from the raw payload (not from ``_sanitize_toggles``, which always
    returns a zeroed ``brute``).  Callers that cannot honour brute force have to
    *say so* rather than quietly drop the switch: silently discarding what the
    operator turned on is the failure mode this whole gate exists to prevent.
    """
    if not isinstance(raw, dict):
        return False
    brute = raw.get("brute")
    if not isinstance(brute, dict):
        return False
    if any(brute.get(key) for key in _INTAKE_BRUTE_FLAGS):
        return True
    return bool(brute.get("max_attempts") or brute.get("rate_limit_per_min"))


def _sanitize_toggles(raw: Any) -> Dict[str, Any]:
    """Normalize intake feature flags and hard-disable brute-force controls.

    Intake records are durable input consumed by a separate runner.  Treat the
    browser payload as untrusted: a caller must never be able to smuggle a
    brute-force request into the queue by setting nested flags.  Keep a stable
    zeroed ``brute`` object for UI/schema compatibility, while allowing the
    non-destructive feature flags to be reviewed by the downstream TargetCard
    gate.
    """
    out: Dict[str, Any] = {}
    if not isinstance(raw, dict):
        return out
    for k in _INTAKE_TOGGLE_KEYS:
        if k in raw:
            out[k] = bool(raw.get(k))
    # Brute force is outside the passive SRC contract.  Always persist an
    # explicit disabled shape so downstream consumers cannot interpret a
    # missing field as "use defaults".
    out["brute"] = {
        **{key: False for key in _INTAKE_BRUTE_FLAGS},
        "max_attempts": 0,
        "rate_limit_per_min": 0,
    }
    return out


def _write_guidance(state_dir: Path, payload: Dict[str, Any]) -> None:
    """P5-e:原子落"续跑指导"请求到 <state_dir>/session_guidance/<id>.json。"""
    d = Path(state_dir) / "session_guidance"
    d.mkdir(parents=True, exist_ok=True)
    gid = str(payload["id"])
    final = d / (gid + ".json")
    tmp = d / ("." + gid + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    replace_with_retry(tmp, final)
