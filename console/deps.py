"""Control-plane constants and validation helpers.

Extracted from the old control_plane monolith: request parsing guards,
the public-target (SSRF) gate, scope normalisation and intake plumbing."""

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


MAX_STATE_FILE_BYTES = 2 * 1024 * 1024
MAX_STATE_EVENTS = 2_000
MAX_VISIBLE_ITEMS = 20
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
    """校验目标为 http(s)/公网域名;拒私网/回环/链路本地/元数据/保留地址(防越权+SSRF 面)。返回归一化目标或空。"""
    s = (raw or "").strip()
    if not (1 <= len(s) <= 300) or " " in s:
        return ""
    cand = s if "://" in s else "http://" + s
    try:
        u = urlparse(cand)
    except Exception:  # noqa: BLE001
        return ""
    if u.scheme not in ("http", "https"):
        return ""
    # Credentials and malformed ports must never enter a durable intake
    # record.  Besides preventing accidental secret persistence, this keeps
    # Console validation aligned with SurfaceScope.check_url().
    if u.username or u.password:
        return ""
    try:
        _ = u.port
    except ValueError:
        return ""
    host = (u.hostname or "").lower()
    if not host or host == "localhost" or host.endswith(".localhost") or "." not in host and not host.replace(":", "").isascii():
        return ""
    try:
        ip = ipaddress.ip_address(host)
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified):
            return ""
    except ValueError:
        if "." not in host:                       # 非 IP 且无点=裸主机名,拒(要公网域名)
            return ""
    return s[:300]


# ---- H1 接入：抓公开页面 + LLM 抽取 scope（公开页面不是打目标，授权门不适用，但 SSRF 门必须留）----

INTAKE_TEXT_MAX = 200_000
INTAKE_PROMPT_CHARS = 30_000
INTAKE_BODY_MAX_BYTES = 1_000_000
INTAKE_MAX_REDIRECTS = 3
INTAKE_MAX_ITEMS = 20
_DOMAIN_NAME_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")

INTAKE_SYSTEM = """\
你在读一个漏洞赏金项目（如 HackerOne program）的页面或文本，目标是把资产范围抽成结构化 JSON。

只输出严格 JSON，不要 markdown fence，不要解释：
{
  "program": "项目名/组织名",
  "in_scope": {"domains": ["example.com"], "hosts": ["api.example.com"], "urls": ["https://api.example.com"]},
  "out_of_scope": ["不在此范围的域名或说明"],
  "candidate_targets": ["https://api.example.com"],
  "notes": "范围要点/限制(可选)"
}

规则：
1. 只抽取页面里**明确列出**的域名/主机/URL，不要脑补、不要扩充。
2. 通配符（如 *.example.com）只保留根域名 example.com，不要保留 *。
3. 不是域名的条目（邮箱、人名、奖项、货币金额）一律丢掉。
4. candidate_targets 只放真正适合先做被动探测的 URL（带参数的 API 优先，静态资源不要）。
5. 页面里没有的信息就留空数组，不要编造。"""

INTAKE_USER_TEMPLATE = """\
来源：{source}

页面/文本内容：
{content}

按系统提示输出严格 JSON。"""


def _normalize_domain(value: Any) -> str:
    """Accept only a public-ish DNS name; drop IP literals and wildcards."""
    name = _text(value, limit=253).lower().lstrip("*.").rstrip(".")
    if not name or not _DOMAIN_NAME_RE.match(name):
        return ""
    try:
        ipaddress.ip_address(name)
        return ""                                  # IP 字面量不作为域名范围
    except ValueError:
        return name


def _normalize_domain_list(values: Any) -> List[str]:
    out: List[str] = []
    for item in (values or [])[:INTAKE_MAX_ITEMS * 2]:
        name = _normalize_domain(item)
        if name and name not in out:
            out.append(name)
    return out[:INTAKE_MAX_ITEMS]


def _url_inside_scope(raw: Any, accepted: Iterable[str]) -> str:
    """Keep only a valid public URL whose host sits inside the accepted scope."""
    target = _valid_public_target(str(raw or ""))
    if not target:
        return ""
    host = (urlparse(target).hostname or "").lower()
    if not host:
        return ""
    for base in accepted:
        if host == base or host.endswith("." + base):
            return target[:300]
    return ""


def _normalize_url_list(values: Any, accepted: Iterable[str]) -> List[str]:
    allowed = [str(item) for item in accepted if item]
    out: List[str] = []
    for item in (values or [])[:INTAKE_MAX_ITEMS * 2]:
        url = _url_inside_scope(item, allowed)
        if url and url not in out:
            out.append(url)
    return out[:INTAKE_MAX_ITEMS]


def _normalize_scope(raw: Any) -> Dict[str, Any]:
    """Sanitize LLM extraction output. The model's answer is untrusted input."""
    data = raw if isinstance(raw, dict) else {}
    in_scope = data.get("in_scope") if isinstance(data.get("in_scope"), dict) else {}
    domains = _normalize_domain_list(in_scope.get("domains"))
    hosts = _normalize_domain_list(in_scope.get("hosts"))
    accepted = domains + hosts
    return {
        "program": _text(data.get("program"), limit=120),
        "in_scope": {
            "domains": domains,
            "hosts": hosts,
            "urls": _normalize_url_list(in_scope.get("urls"), accepted),
        },
        "out_of_scope": [
            _text(item, limit=200) for item in (data.get("out_of_scope") or [])[:INTAKE_MAX_ITEMS]
            if _text(item, limit=200)
        ],
        "candidate_targets": _normalize_url_list(data.get("candidate_targets"), accepted),
        "notes": _text(data.get("notes"), limit=500),
    }


def _http_get_once(url: str, timeout: float) -> Tuple[int, Dict[str, str], bytes]:
    with httpx.Client(follow_redirects=False, timeout=timeout) as client:
        resp = client.get(url, headers={"User-Agent": "Lode-Console/1.0"})
        return resp.status_code, {k.lower(): v for k, v in resp.headers.items()}, resp.content


def _fetch_public_page(
    url: str,
    *,
    timeout: float = 10.0,
    transport: Optional[Callable[[str, float], Tuple[int, Dict[str, str], bytes]]] = None,
) -> Dict[str, Any]:
    """Fetch a public page for intake, re-validating SSRF rules on every hop."""
    get = transport or _http_get_once
    current = _valid_public_target(url)
    if not current:
        return {"ok": False, "url": url[:300], "text": "", "error": "invalid_target"}
    for _ in range(INTAKE_MAX_REDIRECTS + 1):
        request_url = current if "://" in current else "http://" + current
        if not _valid_public_target(request_url):
            return {"ok": False, "url": request_url[:300], "text": "", "error": "invalid_target"}
        try:
            code, headers, body = get(request_url, timeout)
        except Exception as exc:  # noqa: BLE001 - surface a short reason only
            return {"ok": False, "url": request_url[:300], "text": "", "error": f"fetch_failed:{type(exc).__name__}"}
        if code in (301, 302, 303, 307, 308):
            location = str(headers.get("location") or "").strip()
            if not location:
                return {"ok": False, "url": request_url[:300], "text": "", "error": "redirect_without_location"}
            current = urljoin(request_url, location)
            continue
        if code >= 400:
            return {"ok": False, "url": request_url[:300], "text": "", "error": f"http_{code}"}
        content_type = str(headers.get("content-type") or "").lower()
        if content_type and not (content_type.startswith("text/") or content_type.startswith("application/json")):
            return {"ok": False, "url": request_url[:300], "text": "", "error": "unsupported_content_type"}
        text = body[:INTAKE_BODY_MAX_BYTES].decode("utf-8", errors="replace")
        return {"ok": True, "url": request_url[:300], "text": text, "error": ""}
    return {"ok": False, "url": current[:300], "text": "", "error": "too_many_redirects"}


def _extract_scope(content: str, *, source: str, timeout: float = 45.0) -> Dict[str, Any]:
    """Ask the Reasoner-tier model to turn a page/text into a scope draft."""
    if llm_pool is None:
        return {"ok": False, "extracted": None, "error": "llm_pool_unavailable"}
    prompt = INTAKE_USER_TEMPLATE.format(source=source[:200], content=content[:INTAKE_PROMPT_CHARS])
    prefer = os.environ.get("SRC_REASONER_PREFER", "").strip()
    try:
        raw = llm_pool.complete(INTAKE_SYSTEM, prompt, timeout=timeout, prefer=prefer)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "extracted": None, "error": f"llm_failed:{type(exc).__name__}"}
    if not raw:
        return {"ok": False, "extracted": None, "error": "llm_unavailable"}
    from agents.src_agent import _parse_json_response

    parsed = _parse_json_response(raw)
    if parsed is None:
        return {"ok": False, "extracted": None, "error": "extraction_unparseable"}
    extracted = _normalize_scope(parsed)
    if not (extracted["in_scope"]["domains"] or extracted["in_scope"]["hosts"]):
        return {"ok": False, "extracted": extracted, "error": "no_scope_found"}
    return {"ok": True, "extracted": extracted, "error": ""}


def _valid_profile(pid: str) -> str:
    valid = set()
    for key, prof in list_profiles().items():
        valid.add(key)
        for alias in (prof.get("aliases") or []):
            valid.add(str(alias))
    p = _text(pid, limit=80)
    return p if p in valid else ""


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


def _write_intake(state_dir: Path, payload: Dict[str, Any]) -> None:
    """原子落 intake 请求文件到 <state_dir>/project_intake/<intake_id>.json。"""
    d = Path(state_dir) / "project_intake"
    d.mkdir(parents=True, exist_ok=True)
    iid = str(payload["intake_id"])
    final = d / (iid + ".json")
    tmp = d / ("." + iid + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, final)


def _write_guidance(state_dir: Path, payload: Dict[str, Any]) -> None:
    """P5-e:原子落"续跑指导"请求到 <state_dir>/session_guidance/<id>.json。"""
    d = Path(state_dir) / "session_guidance"
    d.mkdir(parents=True, exist_ok=True)
    gid = str(payload["id"])
    final = d / (gid + ".json")
    tmp = d / ("." + gid + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, final)
