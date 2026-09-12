"""Bounded, read-only projections for the local ControlPlane Console."""
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
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, HTTPException, Request, Response, WebSocket, status
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

from core.file_lock import AdvisoryFileLock
from core.operation_profile import list_profiles
from core.src_blackboard import SrcBlackboard

try:                                   # 加密密钥库(可选):有则支持密码解锁明文查看
    from core import key_vault         # type: ignore
except Exception:                      # noqa: BLE001
    key_vault = None                   # type: ignore

try:                                   # #76 情报数据源管理(可选;control_plane 以 root 跑,可直写 sources.json)
    from core import intel_sources     # type: ignore
except Exception:                      # noqa: BLE001
    intel_sources = None               # type: ignore

try:                                   # #53 指纹自修正卡片(可选;console admin=人工门,可 propose/approve/reject)
    from core import fingerprint_corrections as fp_corr  # type: ignore
except Exception:                      # noqa: BLE001
    fp_corr = None                     # type: ignore

try:                                   # #77 attack-graph 联动黑板(只读投影候选链)
    from core import attack_graph      # type: ignore
except Exception:                      # noqa: BLE001
    attack_graph = None                # type: ignore

try:                                   # #77 PTT 活树(只读投影层级任务树)
    from core import ptt_tree          # type: ignore
except Exception:                      # noqa: BLE001
    ptt_tree = None                    # type: ignore

try:                                   # #79 sink 签名库(代码审计护城河;console admin=人工门 approve/reject)
    from core import sink_kb           # type: ignore
except Exception:                      # noqa: BLE001
    sink_kb = None                     # type: ignore

try:                                   # #80 PoC 审批(搬进 Vue,退役 pa-poc-admin;console admin=人工门)
    from core import poc_sync          # type: ignore
except Exception:                      # noqa: BLE001
    poc_sync = None                    # type: ignore

try:                                   # #70 免费 socks 池(验活入池 + 手动添加)
    from core import socks_pool        # type: ignore
except Exception:                      # noqa: BLE001
    socks_pool = None                  # type: ignore

try:                                   # #74 出站 egress 门(被拦列表 + 放行 allowlist + mihomo 规则)
    from core import egress_gate       # type: ignore
except Exception:                      # noqa: BLE001
    egress_gate = None                 # type: ignore

try:                                   # #60 自进化反思卡(console admin=人工门 approve/reject)
    from core import self_evolve       # type: ignore
except Exception:                      # noqa: BLE001
    self_evolve = None                 # type: ignore

try:                                   # #21 代理订阅入口 + socks 入池 mihomo 片段
    from core import proxy_subscriptions  # type: ignore
except Exception:                      # noqa: BLE001
    proxy_subscriptions = None         # type: ignore

try:                                   # F1 对话台芯:读 Strix agents.db 真实多智能体对话
    from core import strix_conversation  # type: ignore
except Exception:                      # noqa: BLE001
    strix_conversation = None          # type: ignore


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


_KEY_UNLOCKS: Dict[str, Tuple[str, float]] = {}   # token -> (vault_password, expires);服务端保存,绝不入 cookie
_KEY_UNLOCK_TTL = 2 * 60 * 60                      # 解锁 2h 后自动回掩


def _unlock_prune(now: float) -> None:
    for t in [t for t, (_, exp) in _KEY_UNLOCKS.items() if exp <= now]:
        _KEY_UNLOCKS.pop(t, None)


def _unlock_pw_for(token: str) -> Optional[str]:
    now = time.time()
    _unlock_prune(now)
    ent = _KEY_UNLOCKS.get(token or "")
    return ent[0] if ent and ent[1] > now else None


class LoginRequest(BaseModel):
    password: str


class ConsoleStaticFiles(StaticFiles):
    """Keep Vite module MIME types stable on hosts with incomplete registries."""

    _MEDIA_TYPES = {".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8"}

    def file_response(self, full_path: str, stat_result: Any, scope: Any, status_code: int = 200) -> Response:
        response = super().file_response(full_path, stat_result, scope, status_code)
        media_type = self._MEDIA_TYPES.get(Path(full_path).suffix.lower())
        if media_type:
            response.headers["content-type"] = media_type
        return response


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


class ProjectIntakeRequest(BaseModel):
    target_url: str
    name: str = ""
    engagement_profile: str = ""
    toggles: Dict[str, Any] = {}


class IntelSourceAddRequest(BaseModel):
    kind: str = "page_watch"
    name: str = ""
    url: str = ""
    extract_hint: str = ""
    query: str = ""
    interval_sec: int = 1800


class IntelSourceToggleRequest(BaseModel):
    id: str
    enabled: bool


class SessionGuidanceRequest(BaseModel):
    session_id: str
    target: str
    guidance: str


class FingerprintCorrectionProposeRequest(BaseModel):
    kind: str
    name: str
    evidence: str
    proposed: Dict[str, Any] | None = None
    target: str | None = None


class FingerprintCorrectionDecisionRequest(BaseModel):
    id: str
    decision: str
    reason: str | None = None


class SinkKbDecisionRequest(BaseModel):
    id: str
    decision: str


class PocConfirmRequest(BaseModel):
    id: str
    approve: bool


class SocksAddRequest(BaseModel):
    addr: str


class ModelActiveRequest(BaseModel):
    name: str


class EgressAllowRequest(BaseModel):
    host: str
    reason: str | None = None


class EvolveDecisionRequest(BaseModel):
    id: str
    decision: str


class ProxySubAddRequest(BaseModel):
    url: str
    name: str | None = None


class ProxySubToggleRequest(BaseModel):
    id: str
    enabled: bool


class SrcAgentStartRequest(BaseModel):
    """Request to start an LLM-driven SRC agent run against a target."""
    target_url: str
    authorization: str = ""
    allowed_domains: List[str] = []
    max_cycles: int = 20
    max_explore: int = 3
    reasoner_prefer: str = "deepseek"


class SrcAgentChatRequest(BaseModel):
    """Send a message to the SRC agent chat."""
    message: str
    session_id: str = ""


class ReadOnlyControlPlane:
    """Replay durable state without using managers that can mutate it on read."""

    def __init__(
        self,
        state_dir: Path | str,
        *,
        now_fn: Callable[[], float] | None = None,
        max_file_bytes: int = MAX_STATE_FILE_BYTES,
        max_events: int = MAX_STATE_EVENTS,
    ) -> None:
        self.state_dir = Path(state_dir)
        self._now = now_fn or time.time
        self.max_file_bytes = max_file_bytes
        self.max_events = max_events

    def _source_path(self, name: str) -> Path:
        return self.state_dir / name

    def _read_events(self, name: str) -> Tuple[List[Dict[str, Any]], str]:
        path = self._source_path(name)
        lock_path = path.with_name(path.name + ".lock")
        try:
            if not path.is_file() or path.is_symlink():
                return [], "missing"
            if not lock_path.is_file() or lock_path.is_symlink():
                return [], "unavailable"
        except OSError:
            return [], "unavailable"

        try:
            with AdvisoryFileLock(lock_path, create=False):
                with path.open("rb") as handle:
                    raw = handle.read(self.max_file_bytes + 1)
        except (OSError, TimeoutError):
            return [], "unavailable"

        partial = len(raw) > self.max_file_bytes
        raw = raw[: self.max_file_bytes]
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return [], "partial"

        events: List[Dict[str, Any]] = []
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                partial = True
                continue
            if not isinstance(event, dict):
                partial = True
                continue
            events.append(event)
            if len(events) >= self.max_events:
                partial = True
                break
        return events, "partial" if partial else "available"

    @staticmethod
    def _summary_status(statuses: Iterable[str]) -> str:
        values = tuple(statuses)
        if values and all(value == "missing" for value in values):
            return "missing"
        if "unavailable" in values:
            return "unavailable"
        if "partial" in values or "missing" in values:
            return "partial"
        return "available"

    def _project_goals(self, events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        goals: Dict[str, Dict[str, Any]] = {}
        for event in events:
            kind = _text(event.get("event"), limit=48)
            if kind == "created":
                raw_goal = event.get("goal")
                if not isinstance(raw_goal, dict):
                    continue
                goal_id = _text(raw_goal.get("goal_id"), limit=128)
                target = _text(raw_goal.get("target"))
                profile_name = _text(raw_goal.get("profile_name"), limit=128)
                if not goal_id or not target or not profile_name:
                    continue
                goals[goal_id] = {
                    "goal_id": goal_id,
                    "target": target,
                    "profile_name": profile_name,
                    "created_at": _number(raw_goal.get("created_at")),
                    "endpoint_count": max(0, int(_number(raw_goal.get("endpoints_total")))),
                    "timebox_seconds": max(1, int(_number(raw_goal.get("timebox_seconds"), 7_200.0))),
                    "audited_endpoints": set(),
                    "finding_count": 0,
                    "verified_finding_count": 0,
                    "rce_confirmed": False,
                }
                continue

            goal = goals.get(_text(event.get("goal_id"), limit=128))
            if goal is None:
                continue
            if kind == "endpoint_audited":
                endpoint = _text(event.get("endpoint"), limit=512)
                if endpoint:
                    goal["audited_endpoints"].add(endpoint)
            elif kind == "finding_recorded":
                finding = event.get("finding")
                if not isinstance(finding, dict):
                    continue
                goal["finding_count"] += 1
                verified = finding.get("verified") is True
                if verified:
                    goal["verified_finding_count"] += 1
                finding_type = _text(finding.get("type"), limit=80).lower()
                if verified and finding_type in {"rce", "remote_code_execution"}:
                    goal["rce_confirmed"] = True

        now = float(self._now())
        snapshots: List[Dict[str, Any]] = []
        for goal in goals.values():
            endpoint_count = int(goal["endpoint_count"])
            audited_count = len(goal["audited_endpoints"])
            stop_condition = None
            if goal["rce_confirmed"]:
                stop_condition = "rce_confirmed"
            elif endpoint_count and audited_count >= endpoint_count:
                stop_condition = "all_endpoints_audited"
            elif now - float(goal["created_at"]) >= int(goal["timebox_seconds"]):
                stop_condition = "timebox_2h" if int(goal["timebox_seconds"]) == 7_200 else "timebox_elapsed"
            snapshots.append(
                {
                    "goal_id": goal["goal_id"],
                    "target": goal["target"],
                    "profile_name": goal["profile_name"],
                    "created_at": goal["created_at"],
                    "endpoint_count": endpoint_count,
                    "audited_endpoint_count": audited_count,
                    "finding_count": goal["finding_count"],
                    "verified_finding_count": goal["verified_finding_count"],
                    "stop_condition": stop_condition,
                }
            )
        return sorted(snapshots, key=lambda item: item["created_at"], reverse=True)[:MAX_VISIBLE_ITEMS]

    def _project_pending_profiles(self, events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        pending: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for event in events:
            kind = _text(event.get("event"), limit=48)
            if kind == "created":
                raw_pending = event.get("pending")
                if not isinstance(raw_pending, dict):
                    continue
                user_id = _text(raw_pending.get("user_id"), limit=256)
                chat_id = _text(raw_pending.get("chat_id"), limit=256)
                target = _text(raw_pending.get("target"))
                goal_id = _text(raw_pending.get("goal_id"), limit=128)
                profiles = _bounded_profiles(raw_pending.get("profile_ids"))
                if user_id and chat_id and target and goal_id and profiles:
                    pending[(user_id, chat_id)] = {
                        "target": target,
                        "goal_id": goal_id,
                        "profiles": profiles,
                        "created_at": _number(raw_pending.get("created_at")),
                        "expires_at": _number(raw_pending.get("expires_at")),
                    }
                continue
            key = (_text(event.get("user_id"), limit=256), _text(event.get("chat_id"), limit=256))
            if kind in {"consumed", "expired"}:
                pending.pop(key, None)

        now = float(self._now())
        current = [item for item in pending.values() if item["expires_at"] > now]
        return sorted(current, key=lambda item: item["expires_at"])[:MAX_VISIBLE_ITEMS]

    def _project_pending_intakes(self, events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Project only review-safe preview fields from the shared intake ledger."""
        pending: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for event in events:
            kind = _text(event.get("event"), limit=48)
            if kind == "preview_created":
                raw = event.get("preview")
                if not isinstance(raw, dict):
                    continue
                user_id = _text(raw.get("user_id"), limit=256)
                chat_id = _text(raw.get("chat_id"), limit=256)
                intake_id = _text(raw.get("intake_id"), limit=128)
                target = _text(raw.get("target"))
                profile = _text(raw.get("profile_name"), limit=128)
                expires_at = _number(raw.get("expires_at"))
                options = raw.get("options") if isinstance(raw.get("options"), dict) else {}
                asset_inventory = options.get("asset_inventory") if isinstance(options.get("asset_inventory"), dict) else {}
                fingerprint = options.get("fingerprint") if isinstance(options.get("fingerprint"), dict) else {}
                intelligence = options.get("intelligence") if isinstance(options.get("intelligence"), dict) else {}
                poc_research = options.get("poc_research") if isinstance(options.get("poc_research"), dict) else {}
                proxy_route = options.get("proxy_route") if isinstance(options.get("proxy_route"), dict) else {}
                if user_id and chat_id and intake_id and target and profile and expires_at > 0:
                    pending[(user_id, chat_id)] = {
                        "intake_id": intake_id,
                        "target": target,
                        "profile_name": profile,
                        "created_at": _number(raw.get("created_at")),
                        "expires_at": expires_at,
                        "asset_inventory_enabled": asset_inventory.get("enabled") is True,
                        "fingerprint_enabled": fingerprint.get("enabled") is True,
                        "intelligence_enabled": intelligence.get("enabled") is True,
                        "poc_research_enabled": poc_research.get("enabled") is True,
                        "proxy_route_enabled": proxy_route.get("enabled") is True,
                    }
                continue
            key = (_text(event.get("user_id"), limit=256), _text(event.get("chat_id"), limit=256))
            if kind in {"confirmed", "preview_expired"}:
                pending.pop(key, None)
        now = float(self._now())
        current = [item for item in pending.values() if item["expires_at"] > now]
        return sorted(current, key=lambda item: item["expires_at"])[:MAX_VISIBLE_ITEMS]

    def _project_tasks(self, events: Iterable[Dict[str, Any]], *, require_profile: bool = True) -> List[Dict[str, Any]]:
        tasks: Dict[str, Dict[str, Any]] = {}
        for event in events:
            task_id = _text(event.get("id"), limit=128)
            if not TASK_ID_RE.fullmatch(task_id):
                continue
            task = tasks.setdefault(
                task_id,
                {
                    "task_id": task_id,
                    "target": "",
                    "goal_id": "",
                    "profile_name": "",
                    "status": "reserved",
                    "created_at": 0.0,
                    "finished_at": 0.0,
                    "run_id": "",
                    "blocked_reason": "",
                },
            )
            target = _text(event.get("target"))
            profile_name = _text(event.get("profile_name"), limit=128)
            goal_id = _text(event.get("goal_id"), limit=128)
            status_value = _text(event.get("status"), limit=64)
            run_id = _text(event.get("run_id"), limit=128)
            if target:
                task["target"] = target
            if profile_name:
                task["profile_name"] = profile_name
            if goal_id:
                task["goal_id"] = goal_id
            if status_value in ALLOWED_TASK_STATUSES:
                task["status"] = status_value
            if run_id and RUN_ID_RE.fullmatch(run_id):
                task["run_id"] = run_id
            if "created_ts" in event:
                task["created_at"] = _number(event.get("created_ts"))
            elif not task["created_at"] and "reserved_ts" in event:
                task["created_at"] = _number(event.get("reserved_ts"))
            if "finished_ts" in event:
                task["finished_at"] = _number(event.get("finished_ts"))
            if task["status"] == "blocked":
                reason = _text(event.get("blocked_reason"), limit=96)
                task["blocked_reason"] = reason if reason in ALLOWED_BLOCK_REASONS else "tool_runner_blocked"

        snapshots = []
        for task in tasks.values():
            if not task["target"] or (require_profile and not task["profile_name"]):
                continue
            snapshots.append(
                {
                    "task_id": task["task_id"],
                    "target": task["target"],
                    "goal_id": task["goal_id"],
                    "profile_name": task["profile_name"],
                    "status": task["status"],
                    "created_at": task["created_at"],
                    "finished_at": task["finished_at"] or None,
                    "run_id": task["run_id"],
                    "blocked_reason": task["blocked_reason"] or None,
                }
            )
        return sorted(snapshots, key=lambda item: item["created_at"], reverse=True)[:MAX_VISIBLE_ITEMS]

    def _project_sandbox_runs(self, tasks: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        cards = []
        for task in tasks:
            task_id = _text(task.get("task_id"), limit=128)
            run_id = _text(task.get("run_id"), limit=128)
            if not TASK_ID_RE.fullmatch(task_id) or not RUN_ID_RE.fullmatch(run_id):
                continue
            card_path = self.state_dir / "strix_tasks" / task_id / "quarantine" / run_id / "sandbox-run.json"
            try:
                if not card_path.is_file() or card_path.is_symlink() or card_path.stat().st_size > MAX_CARD_BYTES:
                    continue
                payload = card_path.read_bytes()
                card = json.loads(payload.decode("utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                continue
            if not isinstance(card, dict) or card.get("schema") != "SandboxRunCard/v1":
                continue
            execution_mode = _text(card.get("execution_mode"), limit=48)
            run_status = _text(card.get("status"), limit=48)
            network = _text(card.get("network"), limit=48)
            rootless = card.get("rootless")
            if execution_mode and run_status and network and isinstance(rootless, bool):
                cards.append(
                    {
                        "task_id": task_id,
                        "run_id": run_id,
                        "status": run_status,
                        "execution_mode": execution_mode,
                        "network": network,
                        "rootless": rootless,
                    }
                )
        return cards[:MAX_VISIBLE_ITEMS]

    @staticmethod
    def _profiles() -> List[Dict[str, str]]:
        profiles = []
        for profile_id, profile in list_profiles().items():
            description = _text(profile.get("description"), limit=160)
            profiles.append({"id": profile_id, "label": description or profile_id})
        return profiles

    # ---- 只读业务面板(复用 py 仪表盘读逻辑;append-only feed 无锁容错读) ----
    def _read_jsonl_plain(self, path: Path, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """无锁容错读(intel_feed/keyleak 等我们自己追加的 feed;末行残缺跳过)。返回尾 limit 条。"""
        out: List[Dict[str, Any]] = []
        try:
            if not path.is_file() or path.is_symlink():
                return []
            raw = path.read_bytes()[:MAX_STATE_FILE_BYTES]
        except OSError:
            return []
        for line in raw.decode("utf-8", "replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(ev, dict):
                out.append(ev)
        return out[-limit:] if limit else out

    def _data_dir(self) -> Path:
        env = os.environ.get("DASHBOARD_DATA_DIR")
        return Path(env) if env else (self.state_dir.parent / "pentest-agent" / "data")

    def _read_json_file(self, path: Path) -> Optional[Dict[str, Any]]:
        try:
            return json.loads(path.read_text(encoding="utf-8")[:MAX_STATE_FILE_BYTES])
        except (OSError, json.JSONDecodeError):
            return None

    def _task_dirs(self) -> Dict[str, Path]:
        """id → 任务输出目录(从 strix_tasks.jsonl 的 output_path 折叠最新)。"""
        out: Dict[str, Path] = {}
        for e in self._read_jsonl_plain(self.state_dir / "strix_tasks.jsonl"):
            tid, op = e.get("id"), e.get("output_path")
            if tid and op:
                out[tid] = Path(str(op))
        return out

    def conversation(self, session_id: str, *, limit: int = 2000) -> Dict[str, Any]:
        """F1 对话台芯:某会话(=task)的 Strix 真实多智能体对话(读 agents.db)。
        {agents:[树], messages:[user/assistant/tool_call/tool_result], counts}。只读,缺库→空。"""
        if strix_conversation is None or not SESSION_ID_RE.fullmatch(str(session_id or "")):
            return {"agents": [], "messages": [], "counts": {}, "session_id": session_id}
        task_dir = self._task_dirs().get(session_id)
        if not task_dir:
            return {"agents": [], "messages": [], "counts": {}, "session_id": session_id}
        try:
            res = strix_conversation.load_for_task(task_dir, limit=max(1, min(5000, limit)))
        except Exception:  # noqa: BLE001
            return {"agents": [], "messages": [], "counts": {}, "session_id": session_id}
        res["session_id"] = session_id
        res.pop("db", None)   # 不外泄绝对路径
        return res

    def conversation_db_path(self, session_id: str) -> Optional[Path]:
        """F3 SSE 用:某会话最新 run 的 agents.db 路径(内部用,不外泄)。"""
        if strix_conversation is None or not SESSION_ID_RE.fullmatch(str(session_id or "")):
            return None
        task_dir = self._task_dirs().get(session_id)
        if not task_dir:
            return None
        try:
            return strix_conversation.find_run_db(task_dir)
        except Exception:  # noqa: BLE001
            return None

    def intel(self, limit: int = 60) -> List[Dict[str, Any]]:
        rows = self._read_jsonl_plain(self.state_dir / "intel_feed.jsonl", limit=limit)
        # The decoupled radar collector stores immutable run artifacts under
        # ``<data_dir>/runs/<run_id>/candidates.jsonl``.  Project its latest
        # candidates into the legacy table shape without copying raw evidence.
        if not rows:
            radar_dir = Path(os.environ.get("PA_INTEL_DATA_DIR", str(self.state_dir / "intel")))
            try:
                run_files = sorted(
                    (p for p in radar_dir.glob("runs/*/candidates.jsonl") if p.is_file() and not p.is_symlink()),
                    key=lambda p: p.stat().st_mtime,
                    reverse=True,
                )
                if run_files:
                    rows = self._read_jsonl_plain(run_files[0], limit=limit)
            except OSError:
                rows = []
        rows.reverse()
        return [{
            "ts": r.get("ts"), "cve": _text(r.get("cve", ""), limit=40),
            "date": _text(r.get("date", ""), limit=12),  # 首次出现(NVD披露日)
            "update_reason": _text(r.get("update_reason", ""), limit=40),  # 状态变化原因(空=首次)
            "severity": _text(r.get("severity", ""), limit=16), "cvss": _text(r.get("cvss", ""), limit=90),
            "title": _text(r.get("title", ""), limit=220), "summary": _text(r.get("summary", ""), limit=320),
            "value": _text(r.get("value", ""), limit=300), "kind": _text(r.get("kind", ""), limit=32),
            "source": _text(r.get("source", ""), limit=120), "tags": [_text(x, limit=32) for x in (r.get("tags") or [])[:8]],
            "score": _number(r.get("score"), 0.0), "has_poc": bool(r.get("has_poc")),
            "poc_source": _text(r.get("poc_source", ""), limit=40), "in_the_wild": bool(r.get("in_the_wild")),
            "refs": [_text(x, limit=220) for x in (r.get("refs") or [])[:3] if x],
        } for r in rows]

    def findings(self, limit: int = 200) -> List[Dict[str, Any]]:
        rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        # 热修(来源可读):task → target 映射,每条发现带出目标与 sarif 落盘时间
        targets: Dict[str, str] = {}
        for e in self._read_jsonl_plain(self.state_dir / "strix_tasks.jsonl"):
            tid, tgt = e.get("id"), _text(e.get("target"))
            if tid and tgt:
                targets[str(tid)] = tgt
        out: List[Dict[str, Any]] = []
        for tid, d in self._task_dirs().items():
            try:
                for sf in d.glob("strix_runs/*/findings.sarif"):
                    sd = self._read_json_file(sf) or {}
                    try:
                        mtime = sf.stat().st_mtime
                    except OSError:
                        mtime = None
                    for run in sd.get("runs", []):
                        for res in run.get("results", []):
                            out.append({
                                "task": tid, "rule": _text(res.get("ruleId", ""), limit=60),
                                "severity": _text((res.get("properties", {}) or {}).get("severity", "info"), limit=16),
                                "title": _text((res.get("message", {}) or {}).get("text", ""), limit=160),
                                "target": targets.get(tid, ""), "ts": mtime})
            except OSError:
                continue
        out.sort(key=lambda f: rank.get(str(f.get("severity")).lower(), 0), reverse=True)
        return out[:limit]

    def keys(self, unlock_pw: Optional[str] = None) -> List[Dict[str, Any]]:
        rows = self._read_jsonl_plain(self._data_dir() / "keyleak" / "seen_keys.jsonl")
        rows = [k for k in rows if not k.get("dropped")]   # 滤掉 DeepSeek 误报丢弃行(否则空 repo 幽灵行混入面板)
        rows.reverse()
        out: List[Dict[str, Any]] = []
        for k in rows[:300]:
            enc = str(k.get("enc") or "")
            rec = {
                "service": _text(k.get("service") or k.get("type_id") or "?", limit=40),
                "repo": _text(k.get("repo", ""), limit=120),
                "path": _text(k.get("path", ""), limit=200),                # 源头文件路径
                "source_url": _text(k.get("url", ""), limit=300),           # GitHub 出处(仅展示外链,绝不 fetch)
                "usable": k.get("usable"),
                "status": _text(k.get("status", ""), limit=12),             # live/dead(回收站)/retry/none
                "tail": _text(k.get("tail", ""), limit=8),
                "detail": _text(k.get("detail", ""), limit=160),            # 只读验活详情
                "assoc_url": _text(k.get("assoc_url", ""), limit=200),   # LLM 从片段推断的关联端点(仅展示,未探测)
                "assoc_kind": _text(k.get("assoc_kind", ""), limit=24),
                "has_enc": bool(enc),                                       # 是否有加密封存的全 key
                "key": "",                                                  # 明文仅在密码解锁窗口内填充
                "ts": k.get("ts"),
            }
            if unlock_pw and enc and key_vault is not None:                 # 解锁窗口:解出明文
                pt = key_vault.unseal(enc, unlock_pw)
                if pt:
                    rec["key"] = pt
            out.append(rec)
        return out

    def profiles_detail(self) -> List[Dict[str, Any]]:
        """7 档 EngagementProfile 明细(镜像 canonical operation_profile 注册表),给 Profiles 页。"""
        out: List[Dict[str, Any]] = []
        for pid, p in list_profiles().items():
            out.append({
                "id": _text(pid, limit=48),
                "label": _text(p.get("description", ""), limit=80) or pid,
                "aliases": [_text(a, limit=40) for a in list(p.get("aliases") or [])[:6]],
                "default_goal": bool(p.get("default_goal")),
                "auto_continue": bool(p.get("auto_continue")),
                "broadcast_level": _text(p.get("broadcast_level", ""), limit=24),
                "stop_conditions": [_text(s, limit=40) for s in list(p.get("stop_conditions") or [])[:5]],
            })
        return out

    def task_detail(self, task_id: str) -> Dict[str, Any]:
        """单任务详情:coverage/expectation/acceptance/scope + 该任务候选发现(给 详情 弹窗)。"""
        if not TASK_ID_RE.match(str(task_id or "")):
            return {}
        d = self._task_dirs().get(task_id)
        if not d:
            return {}
        out: Dict[str, Any] = {"task_id": task_id}
        for name in ("coverage", "expectation", "acceptance", "scope"):
            j = self._read_json_file(d / f"{name}.json")
            if j is not None:
                out[name] = j
        out["findings"] = [f for f in self.findings(limit=200) if f.get("task") == task_id]
        return out

    def system(self) -> Dict[str, Any]:
        mem: Dict[str, Any] = {}
        try:
            info: Dict[str, int] = {}
            for ln in Path("/proc/meminfo").read_text().splitlines():
                key, _, val = ln.partition(":")
                info[key.strip()] = int(val.strip().split()[0]) // 1024
            total, avail = info.get("MemTotal", 0), info.get("MemAvailable", 0)
            mem = {"total_mb": total, "avail_mb": avail,
                   "used_pct": round((total - avail) * 100 / total) if total else 0}
        except Exception:  # noqa: BLE001
            mem = {}
        services: Dict[str, str] = {}
        for n in ("pa-feishu-reply", "pa-mihomo", "pa-poc-admin", "pa-dashboard", "pa-soybean-console"):
            try:
                services[n] = subprocess.run(["systemctl", "is-active", n], capture_output=True,
                                             text=True, timeout=5).stdout.strip() or "unknown"
            except Exception:  # noqa: BLE001
                services[n] = "n/a"
        st = self._read_json_file(self.state_dir / "scheduler_state.json") or {}
        rss = st.get("_rss", {})
        kl = st.get("_keyleak", {})
        ghe = st.get("_github_events", {})
        sv = st.get("_socks_validate", {})
        return {"mem": mem, "services": services, "scheduler": {
            "rss_last_run": rss.get("last_run"), "rss_seen": len(rss.get("seen") or []),
            "rss_last_notified": rss.get("last_notified"), "rss_last_new": rss.get("last_new"),
            "keyleak_last_run": kl.get("last_run"), "keyleak_status": kl.get("last_status"),
            "gh_events_last_run": ghe.get("last_run"), "gh_events_status": ghe.get("last_status"),
            "gh_events_poll": ghe.get("poll_interval"),
            "socks_last_run": sv.get("last_run"), "socks_status": sv.get("last_status")}}

    def models(self) -> Dict[str, Any]:
        """MoA 模型池健康(agent 侧写的 model_pool_status.json;脱敏 host,绝不含 key)。
        R2: 附带当前活跃 provider(读 model_active_provider.json,由 POST /api/v1/model/active 写入)。"""
        j = self._read_json_file(self.state_dir / "model_pool_status.json") or {}
        provs = []
        for p in (j.get("providers") or [])[:20]:
            provs.append({
                "name": _text(p.get("name", ""), limit=32),
                "model": _text(p.get("model", ""), limit=40),
                "host": _text(p.get("host", ""), limit=48),
                "up": bool(p.get("up")),
                "latency_ms": p.get("latency_ms"),
            })
        active = self._read_json_file(self.state_dir / "model_active_provider.json") or {}
        active_name = _text(active.get("name", ""), limit=32)
        active_model = _text(active.get("model", ""), limit=40)
        known = {p["name"] for p in provs}
        return {"checked_at": j.get("checked_at"), "total": j.get("total") or len(provs),
                "up": j.get("up"), "providers": provs,
                "active": active_name if active_name in known else (active_name or None),
                "active_model": active_model or None,
                "active_set_at": active.get("set_at")}

    def set_active_model(self, name: str) -> Dict[str, Any]:
        """R2: 切换活跃 provider。只写 model_active_provider.json(原子替换);
        model_client._providers() 每次调用时读取该文件并把活跃 provider 提到 failover 队首。
        name 必须命中 model_pool_status.json 里已知 provider(不引入 console 侧不可见的新凭据)。"""
        name = (name or "").strip()
        if not name or len(name) > 64 or not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
            return {"ok": False, "error": "invalid_name"}
        j = self._read_json_file(self.state_dir / "model_pool_status.json") or {}
        providers = j.get("providers") or []
        match = next((p for p in providers if p.get("name") == name), None)
        if match is None:
            return {"ok": False, "error": "unknown_provider",
                    "providers": [str(p.get("name", "")) for p in providers][:20]}
        doc = {"name": name, "model": str(match.get("model", ""))[:40],
               "up": bool(match.get("up")), "set_at": time.time(), "set_by": "console"}
        path = self.state_dir / "model_active_provider.json"
        tmp = self.state_dir / ".model_active_provider.json.tmp"
        try:
            tmp.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
            os.replace(tmp, path)
        except OSError:
            return {"ok": False, "error": "write_failed"}
        return {"ok": True, "active": name, "model": doc["model"], "up": doc["up"]}

    def proxy(self) -> Dict[str, Any]:
        """代理池状态(agent 侧写的 proxy_status.json)。出站池=换地区/绕IP封禁,与对外访问代理 49511 无关。"""
        j = self._read_json_file(self.state_dir / "proxy_status.json") or {}
        return {
            "enabled": bool(j.get("enabled")),
            "up": bool(j.get("up")),
            "node": _text(j.get("node", ""), limit=48),
            "node_count": j.get("node_count") or 0,
            "this_round_proxied": bool(j.get("this_round_proxied")),
            "checked_at": j.get("checked_at"),
            "error": _text(j.get("error", ""), limit=40),
        }

    def report(self, task_id: str) -> str:
        if not TASK_ID_RE.match(str(task_id or "")):
            return ""
        d = self._task_dirs().get(task_id)
        if not d:
            return ""
        for cand in (d / "standard_report_cn.md",) + tuple(d.glob("strix_runs/*/penetration_test_report.md")):
            try:
                if cand.is_file():
                    return cand.read_text(encoding="utf-8", errors="replace")[:200_000]
            except OSError:
                continue
        return ""

    # ---- P5-a: 项目 → 会话 → 轨迹(先从既有 goals/tasks 投影;projects/ 下富 events.jsonl 若存在则并入) ----
    @staticmethod
    def _project_slug(target: str) -> str:
        slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(target or "")).strip("-")[:120]
        return slug or "unknown"

    def _goal_snapshots(self) -> List[Dict[str, Any]]:
        # 无锁容错读(与 _task_dirs 同款):P5 只读投影,缺 .lock 也能出数据;不影响 snapshot() 的锁读路径
        return self._project_goals(self._read_jsonl_plain(self.state_dir / "goals.jsonl"))

    def _task_snapshots(self) -> List[Dict[str, Any]]:
        # P5 放宽:只要有 target 就投影(profile 缺失显示 —),便于展示真实历史运行
        return self._project_tasks(self._read_jsonl_plain(self.state_dir / "strix_tasks.jsonl"), require_profile=False)

    def projects(self) -> List[Dict[str, Any]]:
        """一个 target = 一个 project;聚合其 goals(会话)与 tasks(Strix 运行)。"""
        goals = self._goal_snapshots()
        tasks = self._task_snapshots()
        proj: Dict[str, Dict[str, Any]] = {}

        def _ensure(target: str) -> Dict[str, Any]:
            pid = self._project_slug(target)
            return proj.setdefault(pid, {
                "project_id": pid, "target": target, "profiles": set(),
                "session_count": 0, "task_count": 0, "finding_count": 0,
                "verified_finding_count": 0, "running": False, "last_activity": 0.0,
            })

        for g in goals:
            p = _ensure(g["target"])
            if g.get("profile_name"):
                p["profiles"].add(g["profile_name"])
            p["session_count"] += 1
            p["finding_count"] += int(g.get("finding_count") or 0)
            p["verified_finding_count"] += int(g.get("verified_finding_count") or 0)
            p["last_activity"] = max(p["last_activity"], float(g.get("created_at") or 0.0))
            if g.get("stop_condition") is None:
                p["running"] = True
        for t in tasks:
            p = _ensure(t["target"])
            if t.get("profile_name"):
                p["profiles"].add(t["profile_name"])
            p["task_count"] += 1
            p["last_activity"] = max(p["last_activity"], float(t.get("created_at") or 0.0))
            if t.get("status") in {"reserved", "running", "recovery_pending"}:
                p["running"] = True

        out = []
        for p in proj.values():
            out.append({
                "project_id": p["project_id"], "target": p["target"],
                "profiles": sorted(p["profiles"])[:6],
                "session_count": p["session_count"], "task_count": p["task_count"],
                "finding_count": p["finding_count"], "verified_finding_count": p["verified_finding_count"],
                "status": "running" if p["running"] else "done",
                "last_activity": p["last_activity"],
            })
        return sorted(out, key=lambda x: x["last_activity"], reverse=True)[:MAX_VISIBLE_ITEMS]

    def project_detail(self, project_id: str) -> Dict[str, Any]:
        """会话 = goal_id(有 goal 事件则富元数据;没有则从共享该 goal_id 的 tasks 合成;task 无 goal_id 则退回 task_id)。"""
        if not PROJECT_ID_RE.fullmatch(str(project_id or "")):
            return {}
        goals = {g["goal_id"]: g for g in self._goal_snapshots()
                 if self._project_slug(g["target"]) == project_id}
        tasks = [t for t in self._task_snapshots() if self._project_slug(t["target"]) == project_id]
        target = next(iter(goals.values()))["target"] if goals else ""
        tasks_by_key: Dict[str, List[Dict[str, Any]]] = {}
        for t in tasks:
            target = target or t["target"]
            tasks_by_key.setdefault(t.get("goal_id") or t["task_id"], []).append(t)

        def _task_stub(x: Dict[str, Any]) -> Dict[str, Any]:
            return {"task_id": x["task_id"], "status": x["status"], "run_id": x["run_id"]}

        sessions: List[Dict[str, Any]] = []
        for key in list(goals.keys()) + [k for k in tasks_by_key if k not in goals]:
            ktasks = tasks_by_key.get(key, [])
            g = goals.get(key)
            if g is not None:
                sessions.append({
                    "session_id": key, "profile_name": g["profile_name"], "created_at": g["created_at"],
                    "audited_endpoint_count": g["audited_endpoint_count"], "endpoint_count": g["endpoint_count"],
                    "finding_count": g["finding_count"], "verified_finding_count": g["verified_finding_count"],
                    "stop_condition": g["stop_condition"], "status": "done" if g["stop_condition"] else "running",
                    "tasks": [_task_stub(x) for x in ktasks[:MAX_VISIBLE_ITEMS]],
                })
            else:                                      # 只有 task、没有 goal 事件:合成最小会话
                created = max((float(x.get("created_at") or 0.0) for x in ktasks), default=0.0)
                running = any(x["status"] in {"reserved", "running", "recovery_pending"} for x in ktasks)
                prof = next((x["profile_name"] for x in ktasks if x.get("profile_name")), "")
                sessions.append({
                    "session_id": key, "profile_name": prof, "created_at": created,
                    "audited_endpoint_count": 0, "endpoint_count": 0,
                    "finding_count": 0, "verified_finding_count": 0,
                    "stop_condition": None, "status": "running" if running else "done",
                    "tasks": [_task_stub(x) for x in ktasks[:MAX_VISIBLE_ITEMS]],
                })
        sessions.sort(key=lambda s: s["created_at"], reverse=True)
        return {"project_id": project_id, "target": target, "sessions": sessions[:MAX_VISIBLE_ITEMS]}

    def session_trajectory(self, session_id: str) -> List[Dict[str, Any]]:
        """会话轨迹:goals/tasks 原始事件按序投影 + projects/*/sessions/<id>/events.jsonl 富事件并入。"""
        if not SESSION_ID_RE.fullmatch(str(session_id or "")):
            return []
        goal_events = self._read_jsonl_plain(self.state_dir / "goals.jsonl")
        task_events = self._read_jsonl_plain(self.state_dir / "strix_tasks.jsonl")
        traj: List[Dict[str, Any]] = []
        seq = 0
        for ev in goal_events:
            kind = _text(ev.get("event"), limit=48)
            if kind == "created":
                g = ev.get("goal")
                if isinstance(g, dict) and _text(g.get("goal_id"), limit=128) == session_id:
                    traj.append({"seq": seq, "ts": _number(g.get("created_at")), "source": "system",
                                 "kind": "goal_created",
                                 "summary": f"创建目标 {_text(g.get('target'))} · 策略 {_text(g.get('profile_name'), limit=64)}"})
                    seq += 1
                continue
            if _text(ev.get("goal_id"), limit=128) != session_id:
                continue
            if kind == "endpoint_audited":
                ep = _text(ev.get("endpoint"), limit=300)
                if ep:
                    traj.append({"seq": seq, "ts": _number(ev.get("ts")), "source": "tool",
                                 "kind": "endpoint_audited", "summary": f"核销接口 {ep}"})
                    seq += 1
            elif kind == "finding_recorded":
                f = ev.get("finding")
                if isinstance(f, dict):
                    ft = _text(f.get("type"), limit=64)
                    ver = f.get("verified") is True
                    traj.append({"seq": seq, "ts": _number(ev.get("ts")), "source": "finding",
                                 "kind": "finding_recorded",
                                 "summary": f"记录发现 {ft or '?'} · {'已复核' if ver else '候选(待二次确认)'}"})
                    seq += 1
        for ev in task_events:
            tid = _text(ev.get("id"), limit=64)
            if _text(ev.get("goal_id"), limit=128) != session_id and tid != session_id:
                continue
            st = _text(ev.get("status"), limit=48)
            if tid and st:
                ts = _number(ev.get("finished_ts") or ev.get("created_ts") or ev.get("reserved_ts"))
                traj.append({"seq": seq, "ts": ts, "source": "system", "kind": "task_status",
                             "summary": f"任务 {tid} → {st}"})
                seq += 1
        try:                                # 富事件(agent 侧 P5 写入;现在可能没有,best-effort)
            for ejf in (self.state_dir / "projects").glob(f"*/sessions/{session_id}/events.jsonl"):
                for ev in self._read_jsonl_plain(ejf, limit=800):
                    traj.append({"seq": seq, "ts": _number(ev.get("ts")),
                                 "source": _text(ev.get("source"), limit=32) or "agent",
                                 "kind": _text(ev.get("kind"), limit=48),
                                 "summary": _text(ev.get("summary"), limit=300)})
                    seq += 1
        except OSError:
            pass
        return traj[:800]

    def project_intakes(self) -> List[Dict[str, Any]]:
        """列出 console 已提交的新建项目请求(只读投影;status=pending_review,非授权、不代表已开跑)。"""
        d = self.state_dir / "project_intake"
        out: List[Dict[str, Any]] = []
        try:
            files = sorted(d.glob("*.json"), key=lambda p: p.name, reverse=True)
        except OSError:
            return out
        for p in files[:MAX_VISIBLE_ITEMS]:
            j = self._read_json_file(p)
            if not isinstance(j, dict) or j.get("schema") != "ProjectIntakeRequest/v1":
                continue
            tg = j.get("toggles") if isinstance(j.get("toggles"), dict) else {}
            out.append({
                "intake_id": _text(j.get("intake_id"), limit=64),
                "target_url": _text(j.get("target_url"), limit=300),
                "name": _text(j.get("name"), limit=120),
                "engagement_profile": _text(j.get("engagement_profile"), limit=80),
                "status": _text(j.get("status"), limit=32) or "pending_review",
                "created_at": _number(j.get("created_at")),
                "toggle_on": sorted(k for k, v in tg.items() if v is True)[:16],
            })
        return out

    def session_guidance_list(self, session_id: str = "") -> List[Dict[str, Any]]:
        """P5-e:列已提交的续跑指导(可按 session 过滤;只读投影,status=pending_review 非授权)。"""
        d = self.state_dir / "session_guidance"
        out: List[Dict[str, Any]] = []
        try:
            files = sorted(d.glob("*.json"), key=lambda p: p.name, reverse=True)
        except OSError:
            return out
        for p in files[:MAX_VISIBLE_ITEMS * 2]:
            j = self._read_json_file(p)
            if not isinstance(j, dict) or j.get("schema") != "SessionGuidanceRequest/v1":
                continue
            if session_id and _text(j.get("session_id"), limit=128) != session_id:
                continue
            out.append({
                "id": _text(j.get("id"), limit=64),
                "session_id": _text(j.get("session_id"), limit=128),
                "target": _text(j.get("target"), limit=200),
                "guidance": _text(j.get("guidance"), limit=500),
                "status": _text(j.get("status"), limit=32) or "pending_review",
                "created_at": _number(j.get("created_at")),
            })
        return out[:MAX_VISIBLE_ITEMS]

    def fingerprint_corrections(self, status: str = "") -> List[Dict[str, Any]]:
        """#53:列指纹自修正卡(只读投影;可按 status 过滤)。直接读文件,不触发 apply。"""
        d = self.state_dir / "fingerprint_corrections"
        out: List[Dict[str, Any]] = []
        try:
            files = sorted(d.glob("FC-*.json"), key=lambda p: p.name, reverse=True)
        except OSError:
            return out
        for p in files[:MAX_VISIBLE_ITEMS * 3]:
            j = self._read_json_file(p)
            if not isinstance(j, dict) or j.get("schema") != "FingerprintCorrectionCard/v1":
                continue
            st = _text(j.get("status"), limit=16) or "pending"
            if status and st != status:
                continue
            prop = j.get("proposed") if isinstance(j.get("proposed"), dict) else {}
            out.append({
                "id": _text(j.get("id"), limit=64),
                "kind": _text(j.get("kind"), limit=24),
                "name": _text(j.get("name"), limit=64),
                "evidence": _text(j.get("evidence"), limit=600),
                "target": _text(j.get("target"), limit=200),
                "source": _text(j.get("source"), limit=40),
                "status": st,
                "poc_tags": [_text(x, limit=32) for x in (prop.get("poc_tags") or [])][:12],
                "risk": _text(prop.get("risk"), limit=16),
                "created_at": _number(j.get("created_at")),
                "decided_at": _number(j.get("decided_at")),
                "applied_at": _number(j.get("applied_at")),
            })
        out.sort(key=lambda c: c.get("created_at", 0), reverse=True)
        return out[:MAX_VISIBLE_ITEMS * 2]

    def _has_report(self, task_id: str) -> bool:
        d = self._task_dirs().get(task_id)
        if not d:
            return False
        if (d / "standard_report_cn.md").is_file():
            return True
        try:
            return any(d.glob("strix_runs/*/penetration_test_report.md"))
        except OSError:
            return False

    def project_results(self, project_id: str) -> Dict[str, Any]:
        """P5-c 成果一键浏览:某项目跨会话/任务聚合发现 + 可看报告的任务清单 + 严重度概览。"""
        if not PROJECT_ID_RE.fullmatch(str(project_id or "")):
            return {}
        det = self.project_detail(project_id)
        if not det:
            return {}
        task_ids = {t["task_id"] for s in det.get("sessions", []) for t in s.get("tasks", [])}
        proj_findings = [f for f in self.findings(limit=500) if f.get("task") in task_ids]
        sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in proj_findings:
            s = str(f.get("severity", "info")).lower()
            if s in sev:
                sev[s] += 1
        reports = [{"task_id": tid} for tid in sorted(task_ids) if self._has_report(tid)]
        ag: Dict[str, Any] = {}
        if attack_graph is not None:
            try:  # #77 联动候选链(只读投影;闭合危险链的深利用仍走人工门)
                ag = attack_graph.blackboard_summary(self.state_dir, det.get("target", ""))
            except Exception:  # noqa: BLE001
                ag = {}
        ptt: Dict[str, Any] = {}
        if ptt_tree is not None:
            try:  # #77 PTT 活树投影(层级任务树 + 高价值未完成叶子)
                _t = ptt_tree.PTTree.load(self.state_dir, det.get("target", ""))
                if _t.nodes:
                    ptt = _t.summary()
            except Exception:  # noqa: BLE001
                ptt = {}
        return {
            "project_id": project_id, "target": det.get("target", ""),
            "session_count": len(det.get("sessions", [])),
            "severity": sev, "findings": proj_findings[:200], "reports": reports,
            "attack_graph": ag, "ptt": ptt,
        }

    def fleet(self) -> Dict[str, Any]:
        """P5-c 舰队:跨项目当前在跑的 agent(task)+ 各自最新一步轨迹(在干嘛)。并发上限=1 时通常 0-1 条。"""
        running_states = {"reserved", "running", "recovery_pending"}
        running = [t for t in self._task_snapshots() if t.get("status") in running_states]
        out: List[Dict[str, Any]] = []
        for t in running[:MAX_VISIBLE_ITEMS]:
            sid = t.get("goal_id") or t.get("task_id") or ""
            last_summary, last_kind = "", ""
            try:
                traj = self.session_trajectory(sid)
                if traj:
                    last_summary = _text(traj[-1].get("summary"), limit=200)
                    last_kind = _text(traj[-1].get("kind"), limit=48)
            except Exception:  # noqa: BLE001
                pass
            out.append({
                "task_id": t.get("task_id", ""), "project_id": self._project_slug(t.get("target", "")),
                "target": t.get("target", ""), "status": t.get("status", ""),
                "run_id": t.get("run_id", ""), "created_at": t.get("created_at"),
                "last_kind": last_kind, "last_event": last_summary,
            })
        return {"count": len(running), "running": out}

    def asset_changes(self, limit: int = 60) -> List[Dict[str, Any]]:
        """#75 资产 hash 变化事件(agent 侧写的 asset_change_feed.jsonl;只读投影,新→旧)。"""
        rows = self._read_jsonl_plain(self.state_dir / "asset_change_feed.jsonl", limit=limit)
        rows.reverse()
        out: List[Dict[str, Any]] = []
        for r in rows:
            if not isinstance(r, dict) or r.get("schema") != "AssetChangeEvent/v1":
                continue
            out.append({
                "ts": r.get("ts"),
                "target": _text(r.get("target"), limit=200),
                "summary": _text(r.get("summary"), limit=200),
                "new_endpoints": [_text(x, limit=160) for x in (r.get("new_endpoints") or [])[:20]],
                "changed_artifacts": [_text(x, limit=200) for x in (r.get("changed_artifacts") or [])[:20]],
                "new_artifacts": [_text(x, limit=200) for x in (r.get("new_artifacts") or [])[:20]],
                "aggregate_after": _text(r.get("aggregate_after"), limit=64),
            })
        return out

    def list_intel_sources(self) -> List[Dict[str, Any]]:
        """#76 情报数据源列表(读 sources.json;缺则 seed builtin+feeds 投影)。"""
        if intel_sources is None:
            return []
        try:
            srcs = intel_sources.load_sources(self.state_dir)
        except Exception:  # noqa: BLE001
            return []
        out: List[Dict[str, Any]] = []
        for s in (srcs or [])[:100]:
            if not isinstance(s, dict):
                continue
            out.append({
                "id": _text(s.get("id"), limit=64), "kind": _text(s.get("kind"), limit=24),
                "name": _text(s.get("name"), limit=80), "url": _text(s.get("url"), limit=300),
                "enabled": bool(s.get("enabled")), "trusted": bool(s.get("trusted")),
                "tags": [_text(t, limit=24) for t in (s.get("tags") or [])[:6]],
                "status": _text(s.get("last_status") or "untested", limit=24),
                "last_run": _text(s.get("last_run"), limit=32),
                "last_error": _text(s.get("last_error"), limit=300),
                "item_count": int(_number(s.get("item_count"), 0.0)),
                "query": _text(s.get("query"), limit=256),
            })
        return out

    def intel_watch(self) -> Dict[str, Any]:
        """Read-only status for the independent passive-intel watch worker."""
        data_dir = Path(os.environ.get("PA_INTEL_DATA_DIR", str(self.state_dir / "intel")))
        path = data_dir / "watch-state.json"
        value = self._read_json_file(path) or {}
        if not isinstance(value, dict):
            return {"schema": "IntelWatchState/v1", "status": "unknown"}
        return {
            "schema": _text(value.get("schema") or "IntelWatchState/v1", limit=40),
            "status": _text(value.get("status") or "unknown", limit=24),
            "program": _text(value.get("program"), limit=120),
            "started_at": _text(value.get("started_at"), limit=32),
            "last_run_at": _text(value.get("last_run_at"), limit=32),
            "stopped_at": _text(value.get("stopped_at"), limit=32),
            "runs_completed": max(0, int(_number(value.get("runs_completed"), 0))),
            "last_run_id": _text(value.get("last_run_id"), limit=80),
            "consecutive_errors": max(0, int(_number(value.get("consecutive_errors"), 0))),
            "last_error": _text(value.get("last_error"), limit=500),
            "recovered_previous": bool(value.get("recovered_previous")),
            "interval_sec": max(0.0, _number(value.get("interval_sec"), 0.0)),
        }

    def src_autopilot(self) -> Dict[str, Any]:
        """Read-only SRC autopilot/blackboard projection for the local UI.

        The projection intentionally drops result references and raw evidence;
        it exposes only candidate metadata and lease health.  Paths can be
        overridden for deployments that keep the autopilot output separate
        from the control-plane state directory.
        """
        configured = os.environ.get("PA_SRC_BLACKBOARD_PATH", "").strip()
        candidates = [Path(configured)] if configured else [
            self.state_dir / "src-blackboard.json",
            self.state_dir / "src-autopilot" / "src-blackboard.json",
        ]
        board_path = next((path for path in candidates if path.is_file() and not path.is_symlink()), None)
        if board_path is None:
            return {
                "schema": "SrcAutopilotView/v1",
                "available": False,
                "run": {},
                "candidates": [],
                "intents": [],
                "claims": [],
                "dead_ends": [],
                "hints": [],
            }
        try:
            board = SrcBlackboard(board_path).snapshot()
        except (FileNotFoundError, OSError, RuntimeError, TimeoutError):
            return {
                "schema": "SrcAutopilotView/v1",
                "available": False,
                "error": "blackboard_unavailable",
                "run": {},
                "candidates": [],
                "intents": [],
                "claims": [],
                "dead_ends": [],
                "hints": [],
            }

        run_path = Path(os.environ.get("PA_SRC_AUTOPILOT_STATE", str(board_path.with_name("src-autopilot-state.json"))))
        run_raw = self._read_json_file(run_path)
        run = run_raw if isinstance(run_raw, dict) else {}
        facts = {str(item.get("candidate_id")): item for item in board.get("facts", []) if isinstance(item, dict)}
        candidates_view: List[Dict[str, Any]] = []
        for intent in board.get("intents", [])[:MAX_VISIBLE_ITEMS * 5]:
            if not isinstance(intent, dict):
                continue
            cid = _text(intent.get("candidate_id"), limit=80)
            fact = facts.get(cid, {})
            url = _text(fact.get("url") or intent.get("target"), limit=300)
            if not cid or not url:
                continue
            candidates_view.append({
                "candidate_id": cid,
                "intent_id": _text(intent.get("intent_id"), limit=80),
                "url": url,
                "path": _text(urlparse(url).path or "/", limit=220),
                "priority": max(0, min(100, int(_number(fact.get("priority") or intent.get("priority"))))),
                "sources": [_text(item, limit=32) for item in (fact.get("sources") or [])[:8]],
                "phase": _text(intent.get("phase"), limit=64),
                "status": _text(intent.get("status"), limit=24),
                "requires_human_review": intent.get("requires_human_review") is True,
                "updated_at": _number(intent.get("updated_at")),
            })
        candidates_view.sort(key=lambda item: (-int(item["priority"]), item["candidate_id"]))
        intents_view = [{
            "intent_id": _text(item.get("intent_id"), limit=80),
            "candidate_id": _text(item.get("candidate_id"), limit=80),
            "priority": max(0, min(100, int(_number(item.get("priority"))))),
            "phase": _text(item.get("phase"), limit=64),
            "status": _text(item.get("status"), limit=24),
            "requires_human_review": item.get("requires_human_review") is True,
            "updated_at": _number(item.get("updated_at")),
        } for item in board.get("intents", [])[:MAX_VISIBLE_ITEMS * 5] if isinstance(item, dict)]
        claims_view = [{
            "intent_id": _text(item.get("intent_id"), limit=80),
            "worker_id": _text(item.get("worker_id"), limit=120),
            "heartbeat_at": _number(item.get("heartbeat_at")),
            "lease_expires_at": _number(item.get("lease_expires_at")),
        } for item in board.get("claims", [])[:MAX_VISIBLE_ITEMS] if isinstance(item, dict)]
        dead_ends_view = [{
            "intent_id": _text(item.get("intent_id"), limit=80),
            "reason": _text(item.get("reason"), limit=120),
            "detail": _text(item.get("detail"), limit=300),
            "created_at": _number(item.get("created_at")),
        } for item in board.get("dead_ends", [])[-MAX_VISIBLE_ITEMS:] if isinstance(item, dict)]
        hints_view = [{
            "intent_id": _text(item.get("intent_id"), limit=80),
            "hint": _text(item.get("hint"), limit=300),
            "source": _text(item.get("source"), limit=64),
            "created_at": _number(item.get("created_at")),
        } for item in board.get("hints", [])[-MAX_VISIBLE_ITEMS:] if isinstance(item, dict)]
        return {
            "schema": "SrcAutopilotView/v1",
            "available": True,
            "revision": max(0, int(_number(board.get("revision")))),
            "run": {
                "run_id": _text(run.get("run_id"), limit=80),
                "status": _text(run.get("status"), limit=32) or "unknown",
                "round": max(0, int(_number(run.get("current_round")))),
                "max_rounds": max(0, int(_number(run.get("max_rounds")))),
                "stop_reason": _text(run.get("stop_reason"), limit=80),
                "candidate_count": len(candidates_view),
                "no_new_rounds": max(0, int(_number(run.get("no_new_rounds")))),
                "updated_at": _number(run.get("updated_at") or board.get("updated_at")),
            },
            "candidates": candidates_view[:MAX_VISIBLE_ITEMS * 2],
            "intents": intents_view[:MAX_VISIBLE_ITEMS * 2],
            "claims": claims_view,
            "dead_ends": dead_ends_view,
            "hints": hints_view,
        }

    def snapshot(self) -> Dict[str, Any]:
        goals_events, goals_status = self._read_events("goals.jsonl")
        pending_events, pending_status = self._read_events("pending_profiles.jsonl")
        intake_events, intake_status = self._read_events("target_intakes.jsonl")
        task_events, tasks_status = self._read_events("strix_tasks.jsonl")
        tasks = self._project_tasks(task_events)
        return {
            "schema": "ControlPlaneDashboard/v1",
            "generated_at": float(self._now()),
            "state_dir_status": self._summary_status((goals_status, pending_status, intake_status, tasks_status)),
            "profiles": self._profiles(),
            "goals": self._project_goals(goals_events),
            "tasks": tasks,
            "pending_profiles": self._project_pending_profiles(pending_events),
            "pending_intakes": self._project_pending_intakes(intake_events),
            "sandbox_runs": self._project_sandbox_runs(tasks),
            "src_autopilot": self.src_autopilot(),
            "capabilities": {
                "target_intake": "preview_only",
                "approvals": "not_implemented",
                "intelligence": "read_only",
                "findings": "read_only",
                "secret_broker": "read_only",
                "system_health": "read_only",
                "reports": "read_only",
                "tool_runner": "synthetic_only",
            },
        }


def _require_session(request: Request) -> None:
    if request.session.get("control_plane_authenticated") is not True:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication_required")


def _password_matches(submitted: str, expected: str) -> bool:
    """Compare UTF-8 password bytes without leaking where they differ."""
    return hmac.compare_digest(submitted.encode("utf-8"), expected.encode("utf-8"))


def create_app(
    *,
    state_dir: Path | str,
    password: str,
    session_secret: str,
    static_dir: Path | str | None = None,
    dsh_upstream: str | None = None,
    arl_upstream: str | None = None,
) -> FastAPI:
    """Create the same-origin local dashboard service without a public listener."""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError("console_password_too_short")
    if len(session_secret) < MIN_SESSION_SECRET_LENGTH:
        raise ValueError("console_session_secret_too_short")

    app = FastAPI(title="Pentest Agent ControlPlane", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(
        SessionMiddleware,
        secret_key=session_secret,
        session_cookie="pentest_agent_control_plane",
        max_age=12 * 60 * 60,
        same_site="strict",
        https_only=False,
    )
    control_plane = ReadOnlyControlPlane(state_dir)

    @app.get("/healthz")
    def healthz() -> Dict[str, str]:
        return {"status": "ok", "authentication": "required"}

    @app.post("/api/v1/session", status_code=status.HTTP_204_NO_CONTENT)
    def login(payload: LoginRequest, request: Request) -> Response:
        if not _password_matches(payload.password, password):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_credentials")
        request.session.clear()
        request.session["control_plane_authenticated"] = True
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.delete("/api/v1/session", status_code=status.HTTP_204_NO_CONTENT)
    def logout(request: Request) -> Response:
        request.session.clear()
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.get("/api/v1/dashboard")
    def dashboard(request: Request) -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=control_plane.snapshot(), headers={"Cache-Control": "no-store"})

    _NOSTORE = {"Cache-Control": "no-store"}

    @app.get("/api/v1/intel")
    def intel(request: Request, limit: int = 60) -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=control_plane.intel(limit=max(1, min(200, limit))), headers=_NOSTORE)

    @app.get("/api/v1/src-autopilot")
    def src_autopilot(request: Request) -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=control_plane.src_autopilot(), headers=_NOSTORE)

    # ---- SRC Agent background worker state ----
    _src_agent_state: Dict[str, Any] = {
        "status": "idle",  # idle | running | completed | failed
        "run_id": "",
        "target": "",
        "started_at": 0.0,
        "finished_at": 0.0,
        "summary": {},
        "error": "",
        "thread": None,
    }
    _src_agent_lock = threading.Lock()

    def _run_src_agent_background(target_url: str, authorization: str,
                                  allowed_domains: List[str], state_dir_path: Path,
                                  max_cycles: int, max_explore: int,
                                  reasoner_prefer: str) -> None:
        """Background thread: run autopilot → src_agent pipeline."""
        import traceback as _tb
        run_id = f"SA-{int(time.time())}-{secrets.token_hex(3)}"
        with _src_agent_lock:
            _src_agent_state["status"] = "running"
            _src_agent_state["run_id"] = run_id
            _src_agent_state["target"] = target_url
            _src_agent_state["started_at"] = time.time()
            _src_agent_state["finished_at"] = 0.0
            _src_agent_state["summary"] = {}
            _src_agent_state["error"] = ""

        out_dir = state_dir_path / "src-agent-runs" / run_id
        out_dir.mkdir(parents=True, exist_ok=True)
        bb_path = out_dir / "src-blackboard.json"

        try:
            from agents.surface_discovery import SurfaceScope
            from agents.src_autopilot import SrcAutopilot
            from agents.src_agent import run_src_agent

            parsed = urlparse(target_url)
            host = (parsed.hostname or "").lower()
            domains = list(allowed_domains) if allowed_domains else []
            if host and host not in domains:
                # Auto-add the target's domain
                parts = host.split(".")
                if len(parts) >= 2:
                    domains.append(".".join(parts[-2:]))
                else:
                    domains.append(host)

            scope = SurfaceScope(
                program=f"console-{run_id}",
                authorization=authorization or f"Console operator authorized scan of {target_url}",
                allowed_domains=tuple(domains),
                delay_seconds=0.5,
            )

            # Phase 1: Surface discovery + autopilot
            autopilot = SrcAutopilot(
                scope, out_dir / "autopilot-state.json", out_dir,
                max_rounds=3, max_candidates=100,
                blackboard_path=bb_path,
            )
            autopilot.run_round([target_url])

            # Phase 2: LLM agent loop
            summary = run_src_agent(
                bb_path, scope,
                max_cycles=max_cycles,
                max_explore_per_cycle=max_explore,
                reasoner_prefer=reasoner_prefer,
                worker_id=f"console-{run_id}",
            )

            with _src_agent_lock:
                _src_agent_state["status"] = "completed"
                _src_agent_state["finished_at"] = time.time()
                _src_agent_state["summary"] = summary
        except Exception as exc:
            with _src_agent_lock:
                _src_agent_state["status"] = "failed"
                _src_agent_state["finished_at"] = time.time()
                _src_agent_state["error"] = f"{exc.__class__.__name__}: {str(exc)[:300]}"

    @app.post("/api/v1/src-agent/start")
    def src_agent_start(payload: SrcAgentStartRequest, request: Request) -> JSONResponse:
        """Start the LLM-driven SRC agent pipeline in a background thread."""
        _require_session(request)
        target = _valid_public_target(payload.target_url)
        if not target:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_target")
        with _src_agent_lock:
            if _src_agent_state["status"] == "running":
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="agent_already_running")
        state_dir_path = Path(state_dir)
        t = threading.Thread(
            target=_run_src_agent_background,
            args=(target, payload.authorization, payload.allowed_domains,
                  state_dir_path, payload.max_cycles, payload.max_explore,
                  payload.reasoner_prefer),
            daemon=True,
        )
        t.start()
        with _src_agent_lock:
            _src_agent_state["thread"] = t
        return JSONResponse(content={"ok": True, "status": "started", "target": target}, headers=_NOSTORE)

    @app.get("/api/v1/src-agent/status")
    def src_agent_status(request: Request) -> JSONResponse:
        """Check the current SRC agent run status, including blackboard state."""
        _require_session(request)
        with _src_agent_lock:
            result = {k: v for k, v in _src_agent_state.items() if k != "thread"}
        # Append live blackboard snapshot if running
        if result.get("run_id"):
            bb_path = Path(state_dir) / "src-agent-runs" / result["run_id"] / "src-blackboard.json"
            if bb_path.is_file():
                try:
                    bb = SrcBlackboard(bb_path)
                    snap = bb.snapshot()
                    result["blackboard"] = {
                        "facts": len(snap.get("facts", [])),
                        "intents_queued": len([i for i in snap.get("intents", []) if i.get("status") == "queued"]),
                        "intents_completed": len([i for i in snap.get("intents", []) if i.get("status") == "completed"]),
                        "intents_dead_end": len([i for i in snap.get("intents", []) if i.get("status") == "dead_end"]),
                        "intents_blocked": len([i for i in snap.get("intents", []) if i.get("status") == "blocked"]),
                        "dead_ends": len(snap.get("dead_ends", [])),
                        "hints": len(snap.get("hints", [])),
                        "recent_hints": [
                            {"intent_id": h.get("intent_id"), "hint": h.get("hint", "")[:200], "source": h.get("source")}
                            for h in (snap.get("hints") or [])[-10:]
                        ],
                    }
                except Exception:
                    pass
        return JSONResponse(content=result, headers=_NOSTORE)

    @app.post("/api/v1/src-agent/stop")
    def src_agent_stop(request: Request) -> JSONResponse:
        """Request stop of the running SRC agent (best-effort)."""
        _require_session(request)
        with _src_agent_lock:
            if _src_agent_state["status"] != "running":
                return JSONResponse(content={"ok": False, "reason": "not_running"}, headers=_NOSTORE)
            _src_agent_state["status"] = "failed"
            _src_agent_state["error"] = "operator_stopped"
            _src_agent_state["finished_at"] = time.time()
        return JSONResponse(content={"ok": True, "status": "stopped"}, headers=_NOSTORE)

    # ---- SRC Agent interactive chat ----
    try:
        from agents.src_chat import (
            chat as _src_chat,
            _get_or_create_session as _src_get_session,
            list_sessions as _src_list_sessions,
        )
        _src_chat_available = True
    except Exception:
        _src_chat_available = False

    @app.get("/api/v1/src-agent/sessions")
    def src_agent_sessions(request: Request) -> JSONResponse:
        """List all persisted SRC agent sessions (survives restart)."""
        _require_session(request)
        if not _src_chat_available:
            return JSONResponse(content={"sessions": []}, headers=_NOSTORE)
        try:
            sessions = _src_list_sessions(Path(state_dir))
        except Exception:
            sessions = []
        return JSONResponse(content={"sessions": sessions}, headers=_NOSTORE)

    @app.get("/api/v1/src-agent/history")
    def src_agent_history(request: Request, session_id: str = "") -> JSONResponse:
        """Get full message history of a session."""
        _require_session(request)
        if not _src_chat_available:
            return JSONResponse(content={"messages": []}, headers=_NOSTORE)
        if not session_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="missing_session_id")
        session = _src_get_session(session_id, state_dir=Path(state_dir))
        return JSONResponse(content={
            "session_id": session.session_id,
            "messages": session.messages,
            "events": session.events[-50:],
        }, headers=_NOSTORE)

    @app.post("/api/v1/src-agent/chat")
    def src_agent_chat(payload: SrcAgentChatRequest, request: Request) -> JSONResponse:
        """Interactive chat with the SRC agent. The agent can scan targets,
        analyze candidates, fetch URLs, and discuss findings with the operator."""
        _require_session(request)
        if not _src_chat_available:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail="src_chat_module_unavailable")
        message = _text(payload.message, limit=2000).strip()
        if not message:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="empty_message")
        session = _src_get_session(payload.session_id, state_dir=Path(state_dir))
        try:
            reply = _src_chat(session, message, timeout=120.0)
        except Exception as exc:
            reply = f"Error: {exc.__class__.__name__}: {str(exc)[:300]}"
        return JSONResponse(content={
            "session_id": session.session_id,
            "reply": reply,
            "events": session.events[-10:],
        }, headers=_NOSTORE)

    @app.get("/api/v1/src-agent/events")
    def src_agent_events(request: Request, session_id: str = "", since: float = 0) -> JSONResponse:
        """Get recent events from an SRC chat session (for real-time UI updates)."""
        _require_session(request)
        if not _src_chat_available:
            return JSONResponse(content={"events": []}, headers=_NOSTORE)
        session = _src_get_session(session_id, state_dir=Path(state_dir))
        events = [e for e in session.events if e.get("ts", 0) > since]
        return JSONResponse(content={
            "session_id": session.session_id,
            "events": events[-50:],
        }, headers=_NOSTORE)

    @app.get("/api/v1/src-agent/progress")
    def src_agent_progress(request: Request, session_id: str = "") -> JSONResponse:
        """Full test progress summary: targets, findings, dead ends, timeline.

        If no session_id given, aggregates across ALL sessions on disk.
        """
        _require_session(request)
        if not _src_chat_available:
            return JSONResponse(content={"error": "unavailable"}, headers=_NOSTORE)

        if session_id:
            session = _src_get_session(session_id, state_dir=Path(state_dir))
            if session.test_log:
                return JSONResponse(content=session.test_log.summary(), headers=_NOSTORE)
            return JSONResponse(content={"error": "no_test_log"}, headers=_NOSTORE)

        # Aggregate across all sessions
        from core.test_log import SrcTestLog
        chat_dir = Path(state_dir) / "src-chat"
        agg = {
            "schema": "SrcTestSummary/v1",
            "scope": "all-sessions",
            "sessions": 0,
            "totals": {"targets": 0, "scans": 0, "urls_explored": 0,
                       "total_explores": 0, "findings": 0, "dead_ends": 0, "errors": 0},
            "findings": [],
            "targets": {},
        }
        if chat_dir.is_dir():
            for sess_dir in chat_dir.iterdir():
                if not sess_dir.is_dir():
                    continue
                log_path = sess_dir / "src-test-log.jsonl"
                if not log_path.is_file():
                    continue
                agg["sessions"] += 1
                try:
                    sub = SrcTestLog(sess_dir).summary()
                    for k, v in sub.get("totals", {}).items():
                        agg["totals"][k] = agg["totals"].get(k, 0) + (v if isinstance(v, int) else 0)
                    agg["findings"].extend(sub.get("findings", []))
                    for t, info in (sub.get("targets") or {}).items():
                        agg["targets"][t] = info
                except Exception:
                    continue
        agg["findings"] = agg["findings"][-50:]
        return JSONResponse(content=agg, headers=_NOSTORE)

    @app.get("/api/v1/findings")
    def findings(request: Request) -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=control_plane.findings(), headers=_NOSTORE)

    @app.get("/api/v1/keys")
    def keys(request: Request) -> JSONResponse:
        _require_session(request)
        pw = _unlock_pw_for(request.session.get("keys_unlock_token", ""))
        return JSONResponse(content=control_plane.keys(unlock_pw=pw), headers=_NOSTORE)

    @app.post("/api/v1/keys/unlock")
    def keys_unlock(payload: LoginRequest, request: Request) -> JSONResponse:
        _require_session(request)
        if key_vault is None or not key_vault.available():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="vault_unavailable")
        if not key_vault.verify_password(payload.password):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_vault_password")
        now = time.time()
        _unlock_prune(now)
        token = secrets.token_urlsafe(24)
        _KEY_UNLOCKS[token] = (payload.password, now + _KEY_UNLOCK_TTL)
        request.session["keys_unlock_token"] = token
        return JSONResponse(content={"ok": True, "unlocked_until": now + _KEY_UNLOCK_TTL}, headers=_NOSTORE)

    @app.post("/api/v1/keys/lock", status_code=status.HTTP_204_NO_CONTENT)
    def keys_lock(request: Request) -> Response:
        _require_session(request)
        _KEY_UNLOCKS.pop(request.session.get("keys_unlock_token", ""), None)
        request.session.pop("keys_unlock_token", None)
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.get("/api/v1/system")
    def system(request: Request) -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=control_plane.system(), headers=_NOSTORE)

    @app.get("/api/v1/models")
    def models(request: Request) -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=control_plane.models(), headers=_NOSTORE)

    @app.post("/api/v1/model/active")
    def model_active(payload: ModelActiveRequest, request: Request) -> JSONResponse:
        """R2: 切换活跃 LLM provider(写运行时状态文件;model_client 下次调用即生效,无需重启)。"""
        _require_session(request)
        result = control_plane.set_active_model(str(payload.name or ""))
        if not result.get("ok"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail=str(result.get("error", "invalid")))
        return JSONResponse(content=result, headers=_NOSTORE)

    @app.get("/api/v1/proxy")
    def proxy(request: Request) -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=control_plane.proxy(), headers=_NOSTORE)

    @app.get("/api/v1/report")
    def report(request: Request, task_id: str = "") -> Response:
        _require_session(request)
        return Response(content=control_plane.report(task_id), media_type="text/plain; charset=utf-8",
                        headers=_NOSTORE)

    @app.get("/api/v1/profiles")
    def profiles(request: Request) -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=control_plane.profiles_detail(), headers=_NOSTORE)

    @app.get("/api/v1/task")
    def task(request: Request, id: str = "") -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=control_plane.task_detail(id), headers=_NOSTORE)

    @app.get("/api/v1/projects")
    def projects(request: Request) -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=control_plane.projects(), headers=_NOSTORE)

    @app.get("/api/v1/project")
    def project(request: Request, id: str = "") -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=control_plane.project_detail(id), headers=_NOSTORE)

    @app.get("/api/v1/trajectory")
    def trajectory(request: Request, id: str = "") -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=control_plane.session_trajectory(id), headers=_NOSTORE)

    @app.get("/api/v1/conversation")
    def conversation(request: Request, id: str = "", limit: int = 2000) -> JSONResponse:
        """F1 对话台:某会话 Strix 真实多智能体对话(agents.db → user/assistant/tool_call/tool_result + agent 树)。"""
        _require_session(request)
        return JSONResponse(content=control_plane.conversation(id, limit=limit), headers=_NOSTORE)

    def _pending_approvals() -> List[Dict[str, str]]:
        """F5 一等事件:聚合 PoC(#80)/指纹(#53)/反思(#60)待人工确认项,best-effort。"""
        out: List[Dict[str, str]] = []
        try:
            if poc_sync is not None:
                for p in poc_sync.list_pending():
                    pid = _text(p.get("id"), limit=64)
                    if pid:
                        out.append({"approval_id": "poc:" + pid, "gate": "poc",
                                    "summary": _text(f"{p.get('title') or pid} {p.get('cve') or ''}", limit=200)})
        except Exception:  # noqa: BLE001
            pass
        try:
            for c in control_plane.fingerprint_corrections("pending"):
                cid = _text(c.get("id"), limit=64)
                if cid:
                    out.append({"approval_id": "fp:" + cid, "gate": "fingerprint",
                                "summary": _text(f"{c.get('kind') or ''} {c.get('name') or cid}", limit=200)})
        except Exception:  # noqa: BLE001
            pass
        try:
            if self_evolve is not None:
                for c in self_evolve.list_cards(status="pending"):
                    cid = _text(c.get("id"), limit=64)
                    if cid:
                        out.append({"approval_id": "ev:" + cid, "gate": "evolve",
                                    "summary": _text(c.get("text"), limit=120)})
        except Exception:  # noqa: BLE001
            pass
        return out[:MAX_VISIBLE_ITEMS * 3]

    @app.get("/api/v1/conversation/stream")
    async def conversation_stream(request: Request, id: str = "") -> StreamingResponse:
        """F3 SSE 实时:tail agents.db 新增消息(id>last),边跑边冒。替 20s 轮询。
        F5:同通道把待人工确认门作为一等事件推 approval_required/approval_resolved(AG-UI INTERRUPT)。"""
        _require_session(request)
        import asyncio

        async def gen():
            last = 0
            appr_seen: Dict[str, str] = {}
            if strix_conversation is not None:
                db = control_plane.conversation_db_path(id)
            else:
                db = None
            if db is not None:
                try:
                    last = strix_conversation.max_message_id(db)
                except Exception:  # noqa: BLE001
                    last = 0
            yield ": connected\n\n"   # SSE 注释保活
            for _ in range(0, 1800):  # ~1h(2s/轮),客户端断开即止
                if await request.is_disconnected():
                    break
                try:
                    if db is None and strix_conversation is not None:  # run 还没起,重探
                        db = control_plane.conversation_db_path(id)
                    if db is not None:
                        for ev in strix_conversation.load_since(db, last, limit=200):
                            last = ev.get("seq", last)
                            yield "data: " + json.dumps(ev, ensure_ascii=False) + "\n\n"
                except Exception:  # noqa: BLE001
                    pass
                try:
                    current = {a["approval_id"]: a for a in _pending_approvals()}
                    for aid, a in current.items():
                        if aid not in appr_seen:
                            yield "data: " + json.dumps(
                                {"seq": 0, "ts": time.time(), "source": "gate",
                                 "kind": "approval_required", "approval_id": aid,
                                 "gate": a["gate"], "summary": a["summary"]},
                                ensure_ascii=False) + "\n\n"
                    for aid in appr_seen:
                        if aid not in current:
                            yield "data: " + json.dumps(
                                {"seq": 0, "ts": time.time(), "source": "gate",
                                 "kind": "approval_resolved", "approval_id": aid},
                                ensure_ascii=False) + "\n\n"
                    appr_seen = current
                except Exception:  # noqa: BLE001
                    pass
                await asyncio.sleep(2)

        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no", "Connection": "keep-alive"})

    @app.post("/api/v1/session/guidance")
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
            _write_guidance(control_plane.state_dir, rec)
        except OSError:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="write_failed")
        return JSONResponse(content={"ok": True, "id": gid, "status": "pending_review",
                                     "note": "已提交(console 直发,排队处理;若触发人工门会在本页就地支审批按钮)"},
                            headers=_NOSTORE)

    @app.get("/api/v1/session/guidance")
    def session_guidance_list(request: Request, id: str = "") -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=control_plane.session_guidance_list(id), headers=_NOSTORE)

    @app.post("/api/v1/project/intake")
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
            _write_intake(control_plane.state_dir, rec)
        except OSError:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="intake_write_failed")
        return JSONResponse(content={
            "ok": True, "intake_id": iid, "status": "pending_review",
            "note": "已提交(console 直发,排队处理;飞书仅收提醒通知,无审批要求)",
        }, headers=_NOSTORE)

    @app.get("/api/v1/project/intakes")
    def project_intakes(request: Request) -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=control_plane.project_intakes(), headers=_NOSTORE)

    @app.get("/api/v1/project/results")
    def project_results(request: Request, id: str = "") -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=control_plane.project_results(id), headers=_NOSTORE)

    @app.get("/api/v1/fleet")
    def fleet(request: Request) -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=control_plane.fleet(), headers=_NOSTORE)

    @app.get("/api/v1/asset-changes")
    def asset_changes(request: Request, limit: int = 60) -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=control_plane.asset_changes(limit=max(1, min(200, limit))), headers=_NOSTORE)

    @app.get("/api/v1/intel/sources")
    def intel_sources_list(request: Request) -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=control_plane.list_intel_sources(), headers=_NOSTORE)

    @app.get("/api/v1/intel/watch")
    def intel_watch_status(request: Request) -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=control_plane.intel_watch(), headers=_NOSTORE)

    @app.post("/api/v1/intel/sources")
    def intel_sources_add(payload: IntelSourceAddRequest, request: Request) -> JSONResponse:
        """#76 受控写:新增 rss/page_watch 源(校验公网 http(s)+新源默认不可信;直写 sources.json)。"""
        _require_session(request)
        if intel_sources is None:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="intel_sources_unavailable")
        ok, msg = intel_sources.add_source({
            "kind": payload.kind, "name": payload.name, "url": payload.url,
            "interval_sec": payload.interval_sec, "query": payload.query,
            "watch": {"mode": "auto", "extract_hint": payload.extract_hint},
        }, control_plane.state_dir)
        if not ok:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)
        return JSONResponse(content={"ok": True, "id": msg}, headers=_NOSTORE)

    @app.post("/api/v1/intel/sources/toggle", status_code=status.HTTP_204_NO_CONTENT)
    def intel_sources_toggle(payload: IntelSourceToggleRequest, request: Request) -> Response:
        _require_session(request)
        if intel_sources is None:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="intel_sources_unavailable")
        if not intel_sources.set_enabled(payload.id, payload.enabled, control_plane.state_dir):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not_found")
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.delete("/api/v1/intel/sources", status_code=status.HTTP_204_NO_CONTENT)
    def intel_sources_remove(request: Request, id: str = "") -> Response:
        _require_session(request)
        if intel_sources is None:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="intel_sources_unavailable")
        if not intel_sources.remove_source(id, control_plane.state_dir):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not_found")
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.get("/api/v1/fingerprint/corrections")
    def fingerprint_corrections_list(request: Request, status: str = "") -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=control_plane.fingerprint_corrections(status=status), headers=_NOSTORE)

    @app.post("/api/v1/fingerprint/correction")
    def fingerprint_correction_propose(payload: FingerprintCorrectionProposeRequest, request: Request) -> JSONResponse:
        """#53 受控写:提交一张指纹修正卡(pending)。**不生效**——需 admin approve 后由 scheduler 合并进 overlay。"""
        _require_session(request)
        if fp_corr is None:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="fp_corr_unavailable")
        ok, msg = fp_corr.propose_correction(
            control_plane.state_dir, payload.kind, payload.name, payload.evidence,
            proposed=payload.proposed or {}, target=payload.target or "", source="control_plane")
        if not ok:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)
        return JSONResponse(content={"ok": True, "id": msg, "status": "pending",
                                     "note": "已提交,approve 后由 scheduler 合并进 overlay(学习层,可逆)"},
                            headers=_NOSTORE)

    @app.post("/api/v1/fingerprint/correction/decision")
    def fingerprint_correction_decision(payload: FingerprintCorrectionDecisionRequest, request: Request) -> JSONResponse:
        """#53 人工门:admin approve/reject 一张 pending 卡。approve 只置状态,应用由 scheduler 单写。"""
        _require_session(request)
        if fp_corr is None:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="fp_corr_unavailable")
        ok, msg = fp_corr.set_status(control_plane.state_dir, payload.id, payload.decision, reason=payload.reason or "")
        if not ok:
            code = status.HTTP_404_NOT_FOUND if msg == "not_found" else status.HTTP_400_BAD_REQUEST
            raise HTTPException(status_code=code, detail=msg)
        return JSONResponse(content={"ok": True, "id": payload.id, "status": msg}, headers=_NOSTORE)

    @app.get("/api/v1/sink-kb")
    def sink_kb_list(request: Request, status: str = "") -> JSONResponse:
        """#79 sink 签名库(代码审计护城河):stats + 卡片(可按 status 过滤;默认全部)。"""
        _require_session(request)
        if sink_kb is None:
            return JSONResponse(content={"stats": {}, "rows": []}, headers=_NOSTORE)
        try:
            rows = sink_kb.load_all(only_approved=False)
            if status:
                rows = [r for r in rows if r.get("status") == status]
            rows = [{
                "id": _text(r.get("id"), limit=32), "vuln_class": _text(r.get("vuln_class"), limit=32),
                "language": _text(r.get("language"), limit=16), "sink_symbol": _text(r.get("sink_symbol"), limit=160),
                "source": _text(r.get("source"), limit=120), "sanitizer_missing": _text(r.get("sanitizer_missing"), limit=160),
                "cwe": _text(r.get("cwe"), limit=32), "status": _text(r.get("status"), limit=16) or "pending",
                "confidence": _text(r.get("confidence"), limit=16),
                "example_ref": _text(r.get("example_ref"), limit=200),
            } for r in rows[:MAX_VISIBLE_ITEMS * 4]]
            return JSONResponse(content={"stats": sink_kb.stats(), "rows": rows}, headers=_NOSTORE)
        except Exception:  # noqa: BLE001
            return JSONResponse(content={"stats": {}, "rows": []}, headers=_NOSTORE)

    @app.post("/api/v1/sink-kb/decision")
    def sink_kb_decision(payload: SinkKbDecisionRequest, request: Request) -> JSONResponse:
        """#79 人工门:admin approve/reject 一张 sink 签名(approve 才进生效库,query 默认只返 approved)。"""
        _require_session(request)
        if sink_kb is None:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="sink_kb_unavailable")
        if payload.decision not in ("approve", "reject"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="bad_decision")
        ok = sink_kb.approve(payload.id) if payload.decision == "approve" else sink_kb.reject(payload.id)
        if not ok:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not_found")
        return JSONResponse(content={"ok": True, "id": payload.id,
                                     "status": "approved" if payload.decision == "approve" else "rejected"},
                            headers=_NOSTORE)

    @app.get("/api/v1/poc/pending")
    def poc_pending(request: Request) -> JSONResponse:
        """#80 PoC 审批(替代 pa-poc-admin):待确认 PoC + 同步流水日志。"""
        _require_session(request)
        if poc_sync is None:
            return JSONResponse(content={"pending": [], "log": []}, headers=_NOSTORE)
        try:
            return JSONResponse(content={"pending": poc_sync.list_pending(),
                                         "log": poc_sync.sync_log(100)}, headers=_NOSTORE)
        except Exception:  # noqa: BLE001
            return JSONResponse(content={"pending": [], "log": []}, headers=_NOSTORE)

    @app.post("/api/v1/poc/confirm")
    def poc_confirm(payload: PocConfirmRequest, request: Request) -> JSONResponse:
        """#80 人工门:admin approve→PoC 入库 / reject→丢弃(写事件+审计流水,与 pa-poc-admin 同逻辑)。"""
        _require_session(request)
        if poc_sync is None:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="poc_sync_unavailable")
        if not str(payload.id or "").strip():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="missing_id")
        try:
            res = poc_sync.confirm_pending(str(payload.id), approve=bool(payload.approve))
        except Exception:  # noqa: BLE001
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="confirm_failed")
        return JSONResponse(content=res, headers=_NOSTORE)

    @app.get("/api/v1/socks")
    def socks_list(request: Request) -> JSONResponse:
        """#70 免费 socks 池:stats + 全部条目(alive 优先、按延迟排)。"""
        _require_session(request)
        if socks_pool is None:
            return JSONResponse(content={"stats": {}, "rows": []}, headers=_NOSTORE)
        try:
            rows = [{
                "addr": _text(r.get("addr"), limit=80), "status": _text(r.get("status"), limit=8),
                "latency_ms": _number(r.get("latency_ms")), "added_by": _text(r.get("added_by"), limit=16),
                "last_error": _text(r.get("last_error"), limit=40), "last_check": _number(r.get("last_check")),
            } for r in socks_pool.list_all()[:MAX_VISIBLE_ITEMS * 4]]
            return JSONResponse(content={"stats": socks_pool.stats(), "rows": rows}, headers=_NOSTORE)
        except Exception:  # noqa: BLE001
            return JSONResponse(content={"stats": {}, "rows": []}, headers=_NOSTORE)

    @app.post("/api/v1/socks/add")
    def socks_add(payload: SocksAddRequest, request: Request) -> JSONResponse:
        """#70 手动添加一个 socks(立即验活入池)。返回 alive/dead。"""
        _require_session(request)
        if socks_pool is None:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="socks_pool_unavailable")
        ok, msg = socks_pool.add_proxy(str(payload.addr or ""), added_by="console")
        if not ok:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)
        return JSONResponse(content={"ok": True, "addr": str(payload.addr), "result": msg}, headers=_NOSTORE)

    @app.delete("/api/v1/socks", status_code=status.HTTP_204_NO_CONTENT)
    def socks_remove(request: Request, addr: str = "") -> Response:
        _require_session(request)
        if socks_pool is None:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="socks_pool_unavailable")
        if not socks_pool.remove_proxy(addr):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not_found")
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.get("/api/v1/egress")
    def egress_view(request: Request) -> JSONResponse:
        """#74 出站 egress:被拦列表(已自动剔除放行) + 放行 allowlist + 从所有项目 scope 生成的 mihomo 规则。"""
        _require_session(request)
        if egress_gate is None:
            return JSONResponse(content={"blocked": [], "allowlist": [], "mihomo_rules": [], "enforced": False},
                                headers=_NOSTORE)
        try:
            targets = [p.get("target", "") for p in control_plane.projects() if p.get("target")]
        except Exception:  # noqa: BLE001
            targets = []
        try:
            scope = {"targets": targets, "allow_subdomains": True}
            return JSONResponse(content={
                "blocked": egress_gate.list_blocked(limit=100),
                "allowlist": egress_gate.list_allow(),
                "mihomo_rules": egress_gate.mihomo_allowlist_rules(scope),
                "enforced": False,  # mihomo 默认不激活;规则供启用时应用
            }, headers=_NOSTORE)
        except Exception:  # noqa: BLE001
            return JSONResponse(content={"blocked": [], "allowlist": [], "mihomo_rules": [], "enforced": False},
                                headers=_NOSTORE)

    @app.post("/api/v1/egress/allow")
    def egress_allow(payload: EgressAllowRequest, request: Request) -> JSONResponse:
        """#74 放行:admin 把误报 host 加入 allowlist(后续放行 + 从被拦列表自动回顾)。"""
        _require_session(request)
        if egress_gate is None:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="egress_gate_unavailable")
        ok, msg = egress_gate.add_allow(str(payload.host or ""), added_by="console", reason=payload.reason or "")
        if not ok:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)
        return JSONResponse(content={"ok": True, "host": str(payload.host), "result": msg}, headers=_NOSTORE)

    @app.delete("/api/v1/egress/allow", status_code=status.HTTP_204_NO_CONTENT)
    def egress_allow_remove(request: Request, host: str = "") -> Response:
        _require_session(request)
        if egress_gate is None:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="egress_gate_unavailable")
        if not egress_gate.remove_allow(host):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not_found")
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.get("/api/v1/evolve")
    def evolve_list(request: Request, status: str = "") -> JSONResponse:
        """#60 自进化:反思卡 stats + 列表(可按 status 过滤)。"""
        _require_session(request)
        if self_evolve is None:
            return JSONResponse(content={"stats": {}, "rows": []}, headers=_NOSTORE)
        try:
            cards = self_evolve.list_cards(status=status or None)
            rows = [{
                "id": _text(c.get("id"), limit=40), "kind": _text(c.get("kind"), limit=24),
                "text": _text(c.get("text"), limit=800), "category": _text(c.get("category"), limit=40),
                "source": _text(c.get("source"), limit=60), "status": _text(c.get("status"), limit=16) or "pending",
                "created_at": _number(c.get("created_at")),
            } for c in cards[:MAX_VISIBLE_ITEMS * 3]]
            return JSONResponse(content={"stats": self_evolve.stats(), "rows": rows}, headers=_NOSTORE)
        except Exception:  # noqa: BLE001
            return JSONResponse(content={"stats": {}, "rows": []}, headers=_NOSTORE)

    @app.post("/api/v1/evolve/decision")
    def evolve_decision(payload: EvolveDecisionRequest, request: Request) -> JSONResponse:
        """#60 人工门:approve→进生效教训库(下次跑注入)/reject→丢弃。"""
        _require_session(request)
        if self_evolve is None:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="self_evolve_unavailable")
        ok, msg = self_evolve.set_status(str(payload.id or ""), payload.decision)
        if not ok:
            code = status.HTTP_404_NOT_FOUND if msg == "not_found" else status.HTTP_400_BAD_REQUEST
            raise HTTPException(status_code=code, detail=msg)
        return JSONResponse(content={"ok": True, "id": payload.id, "status": msg}, headers=_NOSTORE)

    @app.get("/api/v1/proxy/subscriptions")
    def proxy_subs_list(request: Request) -> JSONResponse:
        """#21 代理订阅 + mihomo 片段(订阅 proxy-providers + #70 存活 socks proxies)。"""
        _require_session(request)
        if proxy_subscriptions is None:
            return JSONResponse(content={"subs": [], "mihomo_snippet": ""}, headers=_NOSTORE)
        try:
            return JSONResponse(content={"subs": proxy_subscriptions.list_subscriptions(),
                                         "mihomo_snippet": proxy_subscriptions.mihomo_snippet(include_socks=True)},
                                headers=_NOSTORE)
        except Exception:  # noqa: BLE001
            return JSONResponse(content={"subs": [], "mihomo_snippet": ""}, headers=_NOSTORE)

    @app.post("/api/v1/proxy/subscriptions")
    def proxy_subs_add(payload: ProxySubAddRequest, request: Request) -> JSONResponse:
        """#21 受控写:加机场订阅(公网 http(s))。生成的 mihomo 片段由用户显式应用,不自动改主配。"""
        _require_session(request)
        if proxy_subscriptions is None:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="proxy_subs_unavailable")
        ok, msg = proxy_subscriptions.add_subscription(str(payload.url or ""), payload.name or "")
        if not ok:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)
        return JSONResponse(content={"ok": True, "id": msg}, headers=_NOSTORE)

    @app.post("/api/v1/proxy/subscriptions/toggle", status_code=status.HTTP_204_NO_CONTENT)
    def proxy_subs_toggle(payload: ProxySubToggleRequest, request: Request) -> Response:
        _require_session(request)
        if proxy_subscriptions is None:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="proxy_subs_unavailable")
        if not proxy_subscriptions.set_enabled(payload.id, payload.enabled):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not_found")
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.delete("/api/v1/proxy/subscriptions", status_code=status.HTTP_204_NO_CONTENT)
    def proxy_subs_remove(request: Request, id: str = "") -> Response:
        _require_session(request)
        if proxy_subscriptions is None:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="proxy_subs_unavailable")
        if not proxy_subscriptions.remove_subscription(id):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not_found")
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    # ---- /dsh/ reverse proxy to the co-located DeepSeek Harness (127.0.0.1:3080) ----
    # dsh serves a SPA with absolute paths (/assets, /plugins, /api incl. a mux
    # WebSocket). We strip the /dsh prefix upstream-side and rewrite absolute
    # references in HTML/JS/CSS bodies so the whole app works same-origin under
    # /dsh/ — no second SSH tunnel needed.
    dsh_base = (dsh_upstream or os.environ.get("PA_DSH_UPSTREAM") or "http://127.0.0.1:3080").rstrip("/")
    dsh_ws_base = "ws" + dsh_base[4:] if dsh_base.startswith("http") else dsh_base
    _DSH_HOP_BY_HOP = {
        "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
        "te", "trailers", "transfer-encoding", "upgrade", "host",
    }
    _DSH_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]

    def _dsh_rewrite_body(content_type: str, body: bytes) -> bytes:
        ctype = content_type.lower()
        if "text/html" in ctype:
            text = body.decode("utf-8", "replace")
            # src="/assets/...", href="/manifest..." and boot-manifest "url":"/plugins/..."
            text = text.replace('="/', '="/dsh/').replace('":"/', '":"/dsh/')
            return text.encode("utf-8")
        if "javascript" in ctype:
            text = body.decode("utf-8", "replace")
            for quote in ('"', "'", "`"):
                text = text.replace(f"{quote}/api", f"{quote}/dsh/api")
                text = text.replace(f"{quote}/plugins/", f"{quote}/dsh/plugins/")
            return text.encode("utf-8")
        if "text/css" in ctype:
            return body.decode("utf-8", "replace").replace("url(/", "url(/dsh/").encode("utf-8")
        return body

    @app.api_route("/dsh", methods=_DSH_METHODS, include_in_schema=False)
    @app.api_route("/dsh/{path:path}", methods=_DSH_METHODS, include_in_schema=False)
    async def dsh_reverse_proxy(request: Request, path: str = "") -> Response:
        _require_session(request)
        upstream_url = f"{dsh_base}/{path}"
        if request.url.query:
            upstream_url += f"?{request.url.query}"
        fwd_headers = {
            k: v for k, v in request.headers.items() if k.lower() not in _DSH_HOP_BY_HOP
        }
        fwd_headers["host"] = urlparse(dsh_base).netloc
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(30.0, read=300.0)) as client:
                upstream = await client.request(
                    request.method,
                    upstream_url,
                    headers=fwd_headers,
                    content=await request.body(),
                    follow_redirects=False,
                )
        except httpx.HTTPError:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="dsh_upstream_unreachable")
        resp_headers: Dict[str, str] = {}
        for key, value in upstream.headers.items():
            lk = key.lower()
            # httpx already decoded the body; stale content-length/encoding must not leak
            if lk in _DSH_HOP_BY_HOP or lk in ("content-length", "content-encoding"):
                continue
            if lk == "location" and value.startswith("/"):
                value = "/dsh" + value
            resp_headers[key] = value
        payload = _dsh_rewrite_body(upstream.headers.get("content-type", ""), upstream.content)
        return Response(content=payload, status_code=upstream.status_code, headers=resp_headers)

    @app.websocket("/dsh/{path:path}")
    async def dsh_websocket_proxy(websocket: WebSocket, path: str) -> None:
        if websocket.scope.get("session", {}).get("control_plane_authenticated") is not True:
            await websocket.close(code=4401)
            return
        import asyncio

        import websockets

        query = websocket.scope.get("query_string", b"").decode()
        target = f"{dsh_ws_base}/{path}" + (f"?{query}" if query else "")
        offered = [p.strip() for p in websocket.headers.get("sec-websocket-protocol", "").split(",") if p.strip()]
        accepted_subprotocol: Optional[str] = None
        try:
            # dsh 校验 WS Origin 必须匹配自身 host;浏览器 Origin 是控制台 origin,必须重写
            async with websockets.connect(
                target, subprotocols=offered or None, max_size=None, origin=dsh_base
            ) as upstream:
                accepted_subprotocol = upstream.subprotocol
                await websocket.accept(subprotocol=accepted_subprotocol)

                async def client_to_upstream() -> None:
                    while True:
                        message = await websocket.receive()
                        if message.get("type") == "websocket.disconnect":
                            return
                        if message.get("bytes") is not None:
                            await upstream.send(message["bytes"])
                        elif message.get("text") is not None:
                            await upstream.send(message["text"])

                async def upstream_to_client() -> None:
                    async for data in upstream:
                        if isinstance(data, bytes):
                            await websocket.send_bytes(data)
                        else:
                            await websocket.send_text(data)

                tasks = [asyncio.ensure_future(client_to_upstream()), asyncio.ensure_future(upstream_to_client())]
                _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for task in pending:
                    task.cancel()
        except Exception:
            if websocket.client_state.name == "CONNECTING":
                # upstream refused/errored before accept: reject the handshake
                try:
                    await websocket.close(code=1011)
                except Exception:
                    pass
                return
        try:
            await websocket.close()
        except Exception:
            pass

    # ---- /arl/ reverse proxy to the co-located ARL-Next frontend (127.0.0.1:5173) ----
    # Same pattern as /dsh/ above, with two ARL-specific twists: the container
    # nginx speaks HTTPS with a self-signed cert (loopback only → verify off),
    # and it gates static assets behind its own basic auth. The upstream
    # credentials come from env PA_ARL_BASIC_AUTH ("user:pass", never committed);
    # the console session remains the outer gate. No WebSocket: ARL frontend polls.
    arl_base = (arl_upstream or os.environ.get("PA_ARL_UPSTREAM") or "https://127.0.0.1:5173").rstrip("/")
    _arl_auth = os.environ.get("PA_ARL_BASIC_AUTH", "").strip()
    _ARL_AUTH_HEADER = ""
    if _arl_auth:
        import base64 as _b64

        _ARL_AUTH_HEADER = "Basic " + _b64.b64encode(_arl_auth.encode("utf-8")).decode("ascii")

    def _arl_rewrite_body(content_type: str, body: bytes) -> bytes:
        ctype = content_type.lower()
        if "text/html" in ctype:
            text = body.decode("utf-8", "replace")
            return text.replace('="/', '="/arl/').replace('":"/', '":"/arl/').encode("utf-8")
        if "javascript" in ctype:
            text = body.decode("utf-8", "replace")
            for quote in ('"', "'", "`"):
                text = text.replace(f"{quote}/api", f"{quote}/arl/api")
                text = text.replace(f"{quote}/assets", f"{quote}/arl/assets")
            return text.encode("utf-8")
        if "text/css" in ctype:
            return body.decode("utf-8", "replace").replace("url(/", "url(/arl/").encode("utf-8")
        return body

    @app.api_route("/arl", methods=_DSH_METHODS, include_in_schema=False)
    @app.api_route("/arl/{path:path}", methods=_DSH_METHODS, include_in_schema=False)
    async def arl_reverse_proxy(request: Request, path: str = "") -> Response:
        _require_session(request)
        upstream_url = f"{arl_base}/{path}"
        if request.url.query:
            upstream_url += f"?{request.url.query}"
        fwd_headers = {
            k: v for k, v in request.headers.items() if k.lower() not in _DSH_HOP_BY_HOP
        }
        fwd_headers["host"] = urlparse(arl_base).netloc
        if _ARL_AUTH_HEADER and "authorization" not in {k.lower() for k in fwd_headers}:
            fwd_headers["Authorization"] = _ARL_AUTH_HEADER
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(30.0, read=300.0), verify=not arl_base.startswith("https")
            ) as client:
                upstream = await client.request(
                    request.method,
                    upstream_url,
                    headers=fwd_headers,
                    content=await request.body(),
                    follow_redirects=False,
                )
        except httpx.HTTPError:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="arl_upstream_unreachable")
        resp_headers: Dict[str, str] = {}
        for key, value in upstream.headers.items():
            lk = key.lower()
            if lk in _DSH_HOP_BY_HOP or lk in ("content-length", "content-encoding"):
                continue
            if lk == "location" and value.startswith("/"):
                value = "/arl" + value
            resp_headers[key] = value
        payload = _arl_rewrite_body(upstream.headers.get("content-type", ""), upstream.content)
        return Response(content=payload, status_code=upstream.status_code, headers=resp_headers)

    resolved_static_dir = Path(static_dir) if static_dir is not None else None

    # ---- Standalone SRC Agent page (no build required) ----
    _src_agent_page = Path(__file__).resolve().parent / "src_agent_page.html"
    if _src_agent_page.is_file():
        @app.get("/src-agent", include_in_schema=False)
        def src_agent_page() -> FileResponse:
            return FileResponse(_src_agent_page)

    if resolved_static_dir is not None and (resolved_static_dir / "index.html").is_file():
        assets_dir = resolved_static_dir / "assets"
        if assets_dir.is_dir():
            app.mount("/assets", ConsoleStaticFiles(directory=str(assets_dir)), name="assets")

        @app.get("/", include_in_schema=False)
        def index() -> FileResponse:
            return FileResponse(resolved_static_dir / "index.html")

        @app.get("/{path:path}", include_in_schema=False)
        def spa_fallback(path: str) -> FileResponse:
            if path.startswith("api/"):
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
            return FileResponse(resolved_static_dir / "index.html")

    return app
