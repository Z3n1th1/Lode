"""Read-only projections over durable Console state.

``ReadOnlyControlPlane`` replays goals/tasks/projects/findings from
append-only JSON/JSONL without using managers that could mutate it."""

import hmac
import hashlib
import ipaddress
import json
import math
import os
import re
import secrets
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple
from urllib.parse import urljoin, urlparse

import httpx
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

from core.file_lock import AdvisoryFileLock, replace_with_retry
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


from console.deps import (
    ALLOWED_BLOCK_REASONS,
    ALLOWED_TASK_STATUSES,
    MAX_CARD_BYTES,
    MAX_PROJECT_PAGE,
    MAX_STATE_EVENTS,
    MAX_STATE_FILE_BYTES,
    MAX_VISIBLE_ITEMS,
    PROJECT_ID_RE,
    RUN_ID_RE,
    SESSION_ID_RE,
    TASK_ID_RE,
    _bounded_profiles,
    _number,
    _text,
)

# 宿主机的 mime 注册表经常认不全前端产物:Windows 上 .woff2/.ttf 直接返回 None,
# 于是文件按 application/octet-stream 送出去,浏览器不保证还当字体解析 ——
# 表现是 @font-face 静默变 error、页面回落到系统字体。所以这里显式写死。
STATIC_MEDIA_TYPES = {
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".woff2": "font/woff2",
    ".woff": "font/woff",
    ".ttf": "font/ttf",
    ".otf": "font/otf",
}


def static_media_type(path: Path | str) -> str | None:
    """按扩展名给出媒体类型;认不出返回 None(交给调用方兜底)。"""
    return STATIC_MEDIA_TYPES.get(Path(path).suffix.lower())


# ---------------------------------------------------------------------------
# 宿主机指标 —— 三个平台各读各的;读不到就返回空,不编造 0。
#
# 原来只读 /proc/meminfo、只 shell 出 `systemctl is-active`,于是非 Linux 机器上
# 「运行」页永远只能显示一排横线 —— 看着像"服务全挂了",其实只是这台机器不是 Linux。
# ---------------------------------------------------------------------------

MONITORED_SERVICES_ENV = "LODE_MONITORED_SERVICES"


def _memory_from_linux(meminfo_path: Path | str = "/proc/meminfo") -> Dict[str, int]:
    info: Dict[str, int] = {}
    for line in Path(meminfo_path).read_text().splitlines():
        key, _, value = line.partition(":")
        info[key.strip()] = int(value.strip().split()[0]) // 1024
    return {"total_mb": info.get("MemTotal", 0), "avail_mb": info.get("MemAvailable", 0)}


def _memory_from_macos(run: Callable[..., Any]) -> Dict[str, int]:
    total = run(["sysctl", "-n", "hw.memsize"], capture_output=True, text=True, timeout=5)
    vm = run(["vm_stat"], capture_output=True, text=True, timeout=5)
    page_size = 4096
    free_pages = 0
    for line in str(vm.stdout).splitlines():
        if "page size of" in line:
            page_size = int(line.split("page size of")[1].split()[0])
        key, _, value = line.partition(":")
        if key.strip() in ("Pages free", "Pages inactive", "Pages speculative"):
            free_pages += int(value.strip().rstrip("."))
    return {"total_mb": int(str(total.stdout).strip()) // (1024 * 1024),
            "avail_mb": free_pages * page_size // (1024 * 1024)}


def _memory_from_windows() -> Dict[str, int]:
    import ctypes

    class MemoryStatusEx(ctypes.Structure):
        _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]

    status = MemoryStatusEx()
    status.dwLength = ctypes.sizeof(MemoryStatusEx)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        return {}
    mib = 1024 * 1024
    return {"total_mb": int(status.ullTotalPhys) // mib, "avail_mb": int(status.ullAvailPhys) // mib}


def host_memory(
    platform_name: Optional[str] = None,
    run: Optional[Callable[..., Any]] = None,
    linux_meminfo: Path | str = "/proc/meminfo",
) -> Dict[str, Any]:
    """{total_mb, avail_mb, used_pct};这台机器读不到就返回 {},让界面显示横线。"""
    name = (platform_name or sys.platform).lower()
    runner = run or subprocess.run
    try:
        if name.startswith("linux"):
            raw = _memory_from_linux(linux_meminfo)
        elif name.startswith("darwin") or name.startswith("macos"):
            raw = _memory_from_macos(runner)
        elif name.startswith("win"):
            raw = _memory_from_windows()
        else:
            raw = {}
    except Exception:  # noqa: BLE001 - 一项宿主机指标读不到,不该让整页 500
        return {}
    total, avail = int(raw.get("total_mb") or 0), int(raw.get("avail_mb") or 0)
    if total <= 0:
        return {}
    return {"total_mb": total, "avail_mb": avail,
            "used_pct": round((total - avail) * 100 / total)}


def monitored_services() -> Tuple[str, ...]:
    """要盯的服务名,来自 LODE_MONITORED_SERVICES(逗号分隔)。

    这里原来写死五个 `pa-*` 单元名:那是某一台机器上的私事,不是这个产品的东西,
    而且在非 Linux 上永远只能是 n/a。现在没配置就一个都不盯,前端那一段自己消失。
    """
    raw = os.environ.get(MONITORED_SERVICES_ENV, "")
    return tuple(name.strip() for name in raw.split(",") if name.strip())


def _service_state_linux(name: str, run: Callable[..., Any]) -> str:
    done = run(["systemctl", "is-active", name], capture_output=True, text=True, timeout=5)
    return str(done.stdout).strip() or "unknown"


def _service_state_macos(name: str, run: Callable[..., Any]) -> str:
    done = run(["launchctl", "list", name], capture_output=True, text=True, timeout=5)
    return "active" if getattr(done, "returncode", 1) == 0 else "inactive"


def _service_state_windows(name: str, run: Callable[..., Any]) -> str:
    done = run(["sc", "query", name], capture_output=True, text=True, timeout=5)
    text = str(done.stdout).upper()
    if "RUNNING" in text:
        return "active"
    if "STOPPED" in text:
        return "inactive"
    return "unknown"


def service_states(
    names: Iterable[str],
    *,
    platform_name: Optional[str] = None,
    run: Optional[Callable[..., Any]] = None,
) -> Dict[str, str]:
    """逐个服务问平台自己的管家:systemd / launchd / 服务控制台。"""
    wanted = [str(name).strip() for name in names if str(name).strip()]
    if not wanted:
        return {}
    name_of_platform = (platform_name or sys.platform).lower()
    runner = run or subprocess.run
    if name_of_platform.startswith("linux"):
        probe: Callable[[str, Callable[..., Any]], str] = _service_state_linux
    elif name_of_platform.startswith("darwin") or name_of_platform.startswith("macos"):
        probe = _service_state_macos
    elif name_of_platform.startswith("win"):
        probe = _service_state_windows
    else:
        return {name: "n/a" for name in wanted}
    states: Dict[str, str] = {}
    for name in wanted:
        try:
            states[name] = probe(name, runner) or "unknown"
        except Exception:  # noqa: BLE001 - 单个服务问不到,其余照常
            states[name] = "n/a"
    return states



class ConsoleStaticFiles(StaticFiles):
    """Keep Vite module MIME types stable on hosts with incomplete registries."""

    def file_response(self, full_path: str, stat_result: Any, scope: Any, status_code: int = 200) -> Response:
        response = super().file_response(full_path, stat_result, scope, status_code)
        media_type = static_media_type(full_path)
        if media_type:
            response.headers["content-type"] = media_type
        return response


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
        # Keep the full projection for aggregation and paginate only at the API
        # boundary. Truncating here makes old goals disappear from project totals
        # once a workspace has more than the visible-page size.
        return sorted(snapshots, key=lambda item: item["created_at"], reverse=True)[:MAX_STATE_EVENTS]

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
        """Project only review-safe preview fields from the shared intake ledger.

        Same ledger the Feishu path writes, so 提交队列 shows exactly the previews
        that are still confirmable — a preview disappears here the moment it is
        confirmed, discarded or left to expire, which is the whole point of
        reading the gate's own log instead of keeping a second list.

        The operator's ``instruction`` stays out, like every other free-text
        field in this projection: it is the one place a secret could ride along,
        and the dialog that needs it reads the gate directly instead.
        """
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
                        # 队列要显示"这次确认到底绑了哪些开关"。
                        "enabled_options": sorted(
                            key for key, value in options.items()
                            if isinstance(value, dict) and value.get("enabled") is True
                        )[:MAX_VISIBLE_ITEMS],
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
                    # 这些是收尾行(cmd_scan/cmd_auto 的 finish_run)才带的量:一个
                    # target 的"面"有多大、它在一次批量里的位置。``has_surface``
                    # 单独记,因为 0 也是个真实的答案(扫了,什么都没有)。
                    "surface_paths": 0,
                    "surface_api": 0,
                    "surface_scripts": 0,
                    "http_status": 0,
                    "batch_index": 0,
                    "batch_size": 0,
                    "has_surface": False,
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
            # 收尾行的量。按键存在来判断,不按真值 —— 0 是"扫了但没面",不是"没记"。
            if any(key in event for key in ("surface_paths", "surface_api",
                                            "surface_scripts", "http_status")):
                task["has_surface"] = True
            if "surface_paths" in event:
                task["surface_paths"] = max(0, int(_number(event.get("surface_paths"))))
            if "surface_api" in event:
                task["surface_api"] = max(0, int(_number(event.get("surface_api"))))
            if "surface_scripts" in event:
                task["surface_scripts"] = max(0, int(_number(event.get("surface_scripts"))))
            if "http_status" in event:
                task["http_status"] = max(0, int(_number(event.get("http_status"))))
            if "batch_index" in event:
                task["batch_index"] = max(0, int(_number(event.get("batch_index"))))
            if "batch_size" in event:
                task["batch_size"] = max(0, int(_number(event.get("batch_size"))))

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
                    "surface_paths": task["surface_paths"],
                    "surface_api": task["surface_api"],
                    "surface_scripts": task["surface_scripts"],
                    "http_status": task["http_status"],
                    "batch_index": task["batch_index"],
                    "batch_size": task["batch_size"],
                    "has_surface": task["has_surface"],
                }
            )
        # 这里以前切 MAX_VISIBLE_ITEMS(=20),而那是**显示**用的常量 —— 于是快照在
        # 数据层就被砍到 20,下游再怎么分页也拿不到第 21 个。这一层不该截断:上界
        # 交给 MAX_STATE_EVENTS(读台账本身的上界),显示由调用方分页。
        return sorted(snapshots, key=lambda item: item["created_at"],
                      reverse=True)[:MAX_STATE_EVENTS]

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

    def findings(self, limit: int = 200) -> List[Dict[str, Any]]:
        rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        from core.finding_workflow import FindingRetestStore, finding_id_for

        retest_rows = FindingRetestStore(self.state_dir / "finding-retests.jsonl").list()
        retests_by_finding: Dict[str, List[Dict[str, Any]]] = {}
        for row in retest_rows:
            retests_by_finding.setdefault(str(row.get("finding_id") or ""), []).append(row)
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
                            rule = _text(res.get("ruleId", ""), limit=60)
                            title = _text((res.get("message", {}) or {}).get("text", ""), limit=160)
                            target = targets.get(tid, "")
                            finding_id = finding_id_for(task=str(tid), rule=rule, title=title, target=target)
                            history = retests_by_finding.get(finding_id, [])
                            latest = history[0] if history else None
                            active = next((item for item in history if item.get("status") in {"pending_review", "queued", "running"}), None)
                            props = (res.get("properties", {}) or {})
                            summary = _text(props.get("summary") or props.get("description") or (res.get("message", {}) or {}).get("text", ""), limit=2000)
                            evidence = _text(props.get("evidence") or props.get("evidence_ref") or "", limit=4000)
                            raw_request = props.get("request") if isinstance(props.get("request"), dict) else {}
                            report_dir = d / "reports"
                            report_file = report_dir / f"{finding_id}.md"
                            report_available = ((not d.is_symlink() and not report_dir.is_symlink() and report_file.is_file())
                                                or self._has_report(str(tid)))
                            out.append({
                                "finding_id": finding_id,
                                "task": tid, "rule": _text(res.get("ruleId", ""), limit=60),
                                "severity": _text((res.get("properties", {}) or {}).get("severity", "info"), limit=16),
                                "title": title,
                                "target": target, "ts": mtime,
                                "summary": summary,
                                "evidence": evidence,
                                "evidence_refs": props.get("evidence_refs") if isinstance(props.get("evidence_refs"), list) else [],
                                # Never project request bodies/headers to the UI.
                                "request_digest": hashlib.sha256(json.dumps(raw_request, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest() if raw_request else "",
                                "report_available": report_available,
                                "retest": {
                                    "status": (active or latest or {}).get("status", "none"),
                                    "verdict": (latest or {}).get("verdict", ""),
                                    "retest_id": (active or latest or {}).get("retest_id", ""),
                                    "human_review_required": bool((active or latest or {}).get("human_review_required", False)),
                                },
                            })
            except OSError:
                continue
        out.sort(key=lambda f: rank.get(str(f.get("severity")).lower(), 0), reverse=True)
        return out[:limit]

    def _finding_row(self, finding_id: str) -> Dict[str, Any]:
        wanted = _text(finding_id, limit=80)
        return next((item for item in self.findings(limit=MAX_VISIBLE_ITEMS)
                     if item.get("finding_id") == wanted), {})

    def _raw_finding_request(self, row: Mapping[str, Any]) -> Dict[str, Any]:
        from core.finding_workflow import finding_id_for

        task_id = str(row.get("task") or "")
        task_dir = self._task_dirs().get(task_id)
        if task_dir is None:
            return {}
        for path in task_dir.glob("strix_runs/*/findings.sarif"):
            document = self._read_json_file(path) or {}
            for run in document.get("runs", []):
                for result in run.get("results", []):
                    rule = _text(result.get("ruleId", ""), limit=60)
                    title = _text((result.get("message", {}) or {}).get("text", ""), limit=160)
                    candidate_id = finding_id_for(task=task_id, rule=rule, title=title,
                                                  target=str(row.get("target") or ""))
                    if candidate_id != row.get("finding_id"):
                        continue
                    properties = result.get("properties", {})
                    request = properties.get("request") if isinstance(properties, dict) else None
                    return dict(request) if isinstance(request, dict) else {}
        return {}

    @staticmethod
    def _has_replay_secret(value: Any, *, key: str = "") -> bool:
        secret_key = re.compile(r"(?i)(?:authorization|cookie|password|passwd|secret|token|api[_-]?key|credential)")
        secret_value = re.compile(r"(?i)\b(?:bearer\s+[a-z0-9._~+/-]+=*|(?:api[_-]?key|token|password|secret)\s*[:=])")
        if secret_key.search(key):
            return True
        if isinstance(value, Mapping):
            return any(ReadOnlyControlPlane._has_replay_secret(v, key=str(k)) for k, v in value.items())
        if isinstance(value, (list, tuple)):
            return any(ReadOnlyControlPlane._has_replay_secret(v) for v in value)
        return isinstance(value, str) and bool(secret_value.search(value))

    def finding_retest_plan(self, finding_id: str) -> Tuple[Dict[str, Any], str]:
        """Build one replay request only from a local SARIF request and saved scope."""
        row = self._finding_row(finding_id)
        if not row:
            return {}, "finding_not_found"
        request = self._raw_finding_request(row)
        if not request:
            return {}, "missing_original_request"
        method = str(request.get("method") or "GET").strip().upper()
        if method not in {"GET", "HEAD", "OPTIONS", "POST"}:
            return {}, "method_not_replayable"
        url = str(request.get("url") or request.get("uri") or "").strip()
        if not url:
            return {}, "missing_original_request_url"
        if not re.match(r"(?i)^https?://", url):
            target_base = str(row.get("target") or "").strip()
            if not target_base:
                return {}, "missing_original_request_origin"
            url = urljoin(target_base.rstrip("/") + "/", url)
        try:
            parsed_request = urlparse(url)
        except ValueError:
            return {}, "original_request_url_invalid"
        if (parsed_request.scheme.lower() not in {"http", "https"} or
                not parsed_request.hostname or parsed_request.username or parsed_request.password):
            return {}, "original_request_url_invalid"
        if self._has_replay_secret(request):
            return {}, "original_request_may_contain_credentials"
        if isinstance(request.get("headers"), Mapping) and request.get("headers"):
            return {}, "original_request_requires_unreplayed_headers"
        body = request.get("body") or ""
        if not isinstance(body, str) or len(body.encode("utf-8")) > 64_000:
            return {}, "original_request_body_invalid"
        task_dir = self._task_dirs().get(str(row.get("task") or ""))
        scope_path = task_dir / "scope.json" if task_dir else None
        if (scope_path is None or task_dir is None or task_dir.is_symlink() or
                scope_path.is_symlink() or not scope_path.is_file()):
            return {}, "original_scope_unavailable"
        scope_doc = self._read_json_file(scope_path)
        if not isinstance(scope_doc, dict):
            return {}, "original_scope_unreadable"
        from agents.surface_discovery import SurfaceScope
        try:
            scope = SurfaceScope.from_mapping(scope_doc)
            scope.require_authorization()
            allowed, reason = scope.check_url(url)
        except (TypeError, ValueError):
            return {}, "original_scope_invalid"
        if not allowed:
            return {}, f"request_outside_original_scope:{reason}"
        if not scope.allows_method(method):
            return {}, "method_not_in_original_scope"
        if body and not scope.allow_request_body:
            return {}, "body_not_in_original_scope"
        # The automated runner needs a response oracle from the finding record.
        # An HTTP status alone is not enough to claim that a vulnerability persists.
        expected = request.get("expected") if isinstance(request.get("expected"), dict) else {}
        expected_hash = str(expected.get("sha256_12") or request.get("response_sha256_12") or "").strip()
        markers = expected.get("markers") if isinstance(expected.get("markers"), list) else request.get("response_markers")
        markers = [str(value)[:200] for value in markers[:10] if isinstance(value, str) and value] if isinstance(markers, list) else []
        if not expected_hash and not markers:
            return {}, "missing_original_response_oracle"
        return {
            "url": url, "method": method, "body": body,
            "content_type": str(request.get("content_type") or "")[:120],
            "expected_status": expected.get("status", request.get("response_status")),
            "expected_sha256_12": expected_hash,
            "response_markers": markers,
            "scope_document": scope_doc,
            "scope_ref": str(scope_path),
        }, ""

    def finding_detail(self, finding_id: str) -> Dict[str, Any]:
        """Return one finding plus report/retest history for the Console panel."""
        from core.finding_workflow import FindingRetestStore, report_template

        wanted = _text(finding_id, limit=80)
        row = self._finding_row(wanted)
        if not row:
            return {}
        task_id = str(row.get("task") or "")
        output_dir = self._task_dirs().get(task_id)
        report = ""
        if output_dir:
            custom = output_dir / "reports" / f"{wanted}.md"
            try:
                if (not output_dir.is_symlink() and not custom.parent.is_symlink() and custom.is_file()
                        and custom.resolve().is_relative_to(output_dir.resolve())):
                    report = custom.read_text(encoding="utf-8", errors="replace")[:200_000]
            except OSError:
                pass
        retests = FindingRetestStore(self.state_dir / "finding-retests.jsonl").list(wanted)
        digest_material = json.dumps({key: row.get(key) for key in ("finding_id", "task", "rule", "title", "target", "summary", "evidence", "evidence_refs", "request_digest")}, ensure_ascii=False, sort_keys=True)
        evidence_digest = hashlib.sha256(digest_material.encode("utf-8")).hexdigest()
        _plan, plan_reason = self.finding_retest_plan(wanted)
        return {
            "finding": row,
            "report": report,
            "report_template": report_template(row, retests=retests),
            "retests": retests,
            "evidence_digest": evidence_digest,
            "auto_retest_available": bool(_plan),
            "auto_retest_reason": ("自动复测会重放已留档的单个请求，沿用原授权 scope，并通过 Lode 操作语义、速率、预算和审计闸门。" if _plan else f"不能自动重放：{plan_reason}。可补充人工复测记录。"),
        }

    def profiles_detail(self) -> List[Dict[str, Any]]:
        """6 档 EngagementProfile 明细(镜像 canonical operation_profile 注册表),给 Profiles 页。"""
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
        st = self._read_json_file(self.state_dir / "scheduler_state.json") or {}
        rss = st.get("_rss", {})
        kl = st.get("_keyleak", {})
        ghe = st.get("_github_events", {})
        sv = st.get("_socks_validate", {})
        return {"mem": host_memory(), "services": service_states(monitored_services()), "scheduler": {
            "rss_last_run": rss.get("last_run"), "rss_seen": len(rss.get("seen") or []),
            "rss_last_notified": rss.get("last_notified"), "rss_last_new": rss.get("last_new"),
            "keyleak_last_run": kl.get("last_run"), "keyleak_status": kl.get("last_status"),
            "gh_events_last_run": ghe.get("last_run"), "gh_events_status": ghe.get("last_status"),
            "gh_events_poll": ghe.get("poll_interval"),
            "socks_last_run": sv.get("last_run"), "socks_status": sv.get("last_status")}}

    def _configured_providers(self) -> List[Dict[str, Any]]:
        """本机 LLM_PROVIDERS 解析出来的 provider 配了哪些。

        这是 agent 侧从没写过 ``model_pool_status.json`` 时的兜底:那份文件没人写时,
        「模型上游」永远是一张空表,看起来像全挂了 —— 其实只是没人探测过。
        只取 name/base_url/model:``parse_providers()`` 的返回值里有 api_key,
        这里**绝不**把它带出去;host 只留 urlparse 的 netloc,path/query 都丢掉。
        """
        if llm_pool is None:
            return []
        try:
            providers = llm_pool.parse_providers()
        except Exception:  # noqa: BLE001 - 配置坏了不该把这一页整个打掉
            return []
        out: List[Dict[str, Any]] = []
        for p in providers[:20]:
            out.append({
                "name": _text(p.get("name", ""), limit=32),
                "model": _text(p.get("model", ""), limit=40),
                "host": _text(urlparse(str(p.get("base_url") or "")).netloc, limit=48),
                "up": None,          # 没探测过 —— 不是"挂了"
                "latency_ms": None,
                "probed": False,
            })
        return out

    def models(self) -> Dict[str, Any]:
        """MoA 模型池健康。脱敏 host,绝不含 key。

        两段式:优先 agent 侧写的 ``model_pool_status.json``(带真实探测结果 up/latency);
        它不在时退回本机配置(``LLM_PROVIDERS``),provider 列得出来但 ``probed=false``。
        没有这层兜底,这一页就只有一张空表,而"配了没探测"和"探了全挂"长得一样。
        R2: 附带当前活跃 provider(读 model_active_provider.json,由 POST /api/v1/model/active 写入)。
        """
        j = self._read_json_file(self.state_dir / "model_pool_status.json") or {}
        probed: List[Dict[str, Any]] = []
        for p in (j.get("providers") or [])[:20]:
            probed.append({
                "name": _text(p.get("name", ""), limit=32),
                "model": _text(p.get("model", ""), limit=40),
                "host": _text(p.get("host", ""), limit=48),
                "up": bool(p.get("up")),
                "latency_ms": p.get("latency_ms"),
                "probed": True,
            })
        if probed:
            provs, source = probed, "status_file"
        else:
            provs = self._configured_providers()
            source = "configured" if provs else "none"
        active = self._read_json_file(self.state_dir / "model_active_provider.json") or {}
        active_name = _text(active.get("name", ""), limit=32)
        active_model = _text(active.get("model", ""), limit=40)
        known = {p["name"] for p in provs}
        return {"checked_at": j.get("checked_at") if probed else None,
                "probed": bool(probed), "source": source,
                "total": (j.get("total") if probed else None) or len(provs),
                "up": j.get("up") if probed else None, "providers": provs,
                "active": active_name if active_name in known else (active_name or None),
                "active_model": active_model or None,
                "active_set_at": active.get("set_at")}

    def set_active_model(self, name: str) -> Dict[str, Any]:
        """R2: 切换活跃 provider。只写 model_active_provider.json(原子替换);
        core.llm_pool 每次调用时读取该文件并把活跃 provider 提到 failover 队首。
        name 必须命中池内已知 provider(不引入 console 侧不可见的新凭据)。池的来源与
        GET /api/v1/models 一致:探测结果优先,本机配置兜底。"""
        name = (name or "").strip()
        if not name or len(name) > 64 or not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
            return {"ok": False, "error": "invalid_name"}
        by_name = {p["name"]: p for p in (self.models().get("providers") or [])}
        match = by_name.get(name)
        if match is None:
            return {"ok": False, "error": "unknown_provider",
                    "providers": sorted(by_name)[:20]}
        doc = {"name": name, "model": str(match.get("model", ""))[:40],
               "up": match.get("up"), "set_at": time.time(), "set_by": "console"}
        path = self.state_dir / "model_active_provider.json"
        tmp = self.state_dir / ".model_active_provider.json.tmp"
        try:
            tmp.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
            replace_with_retry(tmp, path)
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
        for cand in (d / "standard_report_cn.md",) + tuple(d.glob("reports/*.md")) + tuple(d.glob("strix_runs/*/penetration_test_report.md")):
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

    def projects(self, *, offset: int = 0, limit: int = MAX_VISIBLE_ITEMS) -> Dict[str, Any]:
        """一个 target = 一个 project;聚合其 goals(会话)与 tasks(Strix 运行)。

        分页返回,并且**把总数带出去**。以前这里是 ``[:MAX_VISIBLE_ITEMS]`` 的静默
        截断,而页头照抄列表长度 —— 于是"最近 20 个"在界面上就是"一共 20 个"。
        跑一个 252 台主机的 scope 时,操作员没有任何办法知道后面还有 232 个。
        """
        goals = self._goal_snapshots()
        tasks = self._task_snapshots()
        proj: Dict[str, Dict[str, Any]] = {}

        def _ensure(target: str) -> Dict[str, Any]:
            pid = self._project_slug(target)
            return proj.setdefault(pid, {
                "project_id": pid, "target": target, "profiles": set(),
                # 会话是**键的集合**,不是计数器:同一个 goal_id 下的多个 task 是
                # 一个会话,不能数成多个。键的口径和 project_detail() 逐字相同
                # (goal_id 优先,退回 task_id),列表和详情才不会各说一套。
                "sessions": set(), "task_count": 0, "finding_count": 0,
                "verified_finding_count": 0, "running": False, "last_activity": 0.0,
                "running_task": None, "latest_task": None, "surface_task": None,
            })

        def _newer(candidate: Dict[str, Any], current: Optional[Dict[str, Any]]) -> bool:
            if current is None:
                return True
            return float(candidate.get("created_at") or 0.0) >= float(current.get("created_at") or 0.0)

        for g in goals:
            p = _ensure(g["target"])
            if g.get("profile_name"):
                p["profiles"].add(g["profile_name"])
            p["sessions"].add(g["goal_id"])
            p["finding_count"] += int(g.get("finding_count") or 0)
            p["verified_finding_count"] += int(g.get("verified_finding_count") or 0)
            p["last_activity"] = max(p["last_activity"], float(g.get("created_at") or 0.0))
            if g.get("stop_condition") is None:
                p["running"] = True
        for t in tasks:
            p = _ensure(t["target"])
            if t.get("profile_name"):
                p["profiles"].add(t["profile_name"])
            p["sessions"].add(t.get("goal_id") or t["task_id"])
            p["task_count"] += 1
            p["last_activity"] = max(p["last_activity"], float(t.get("created_at") or 0.0))
            if t.get("status") in {"reserved", "running", "recovery_pending"}:
                p["running"] = True
                if _newer(t, p["running_task"]):
                    p["running_task"] = t
            if _newer(t, p["latest_task"]):
                p["latest_task"] = t
            # 面计数取"最近一次带面结果的运行"。重扫时 running 行还没有面,所以
            # 用 surface_task 而不是 latest_task —— 否则一行 running 会把上一趟
            # 真实的面数擦成 0。
            if t.get("has_surface") and _newer(t, p["surface_task"]):
                p["surface_task"] = t

        out = []
        for p in proj.values():
            running_task = p["running_task"]
            # 位置(137/325)跟着在跑的那条走;没在跑就退回最近一条。
            position = running_task or p["latest_task"] or {}
            surface = p["surface_task"] or {}
            out.append({
                "project_id": p["project_id"], "target": p["target"],
                "profiles": sorted(p["profiles"])[:6],
                "session_count": len(p["sessions"]), "task_count": p["task_count"],
                "finding_count": p["finding_count"], "verified_finding_count": p["verified_finding_count"],
                "status": "running" if p["running"] else "done",
                "last_activity": p["last_activity"],
                "running_task_id": (running_task or {}).get("task_id", ""),
                "batch_index": max(0, int(position.get("batch_index") or 0)),
                "batch_size": max(0, int(position.get("batch_size") or 0)),
                "surface_paths": max(0, int(surface.get("surface_paths") or 0)),
                "surface_api": max(0, int(surface.get("surface_api") or 0)),
                "surface_scripts": max(0, int(surface.get("surface_scripts") or 0)),
                "http_status": max(0, int(surface.get("http_status") or 0)),
                "has_surface": bool(surface),
            })
        ordered = sorted(out, key=lambda x: x["last_activity"], reverse=True)
        try:
            start = max(0, int(offset))
        except (TypeError, ValueError):
            start = 0
        try:
            size = max(1, min(int(limit), MAX_PROJECT_PAGE))
        except (TypeError, ValueError):
            size = MAX_VISIBLE_ITEMS
        # 顶部横幅取全局那一条 running,而不是当前页里的 —— 否则翻到第 9 页时
        # "正在扫哪台"就消失了,而那跟你在第几页没有任何关系。
        running = next(
            ({"project_id": o["project_id"], "target": o["target"],
              "task_id": o["running_task_id"], "batch_index": o["batch_index"],
              "batch_size": o["batch_size"]}
             for o in ordered if o["running_task_id"]),
            None,
        )
        return {"projects": ordered[start:start + size], "total": len(ordered),
                "offset": start, "limit": size, "running": running}

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

    def pending_intakes(self) -> Dict[str, Any]:
        """待确认的建目标预览(提交队列)。读的是门自己的 target_intakes.jsonl。

        这里以前扫 state_dir/project_intake/*.json —— 那是 console 旧路径写下的
        请求文件,没有任何消费者。现在没有第二份列表:预览一旦被确认/放弃/过期,
        它在这条队列里就消失了。

        把读取状态一起返回:空队列有两种意思 —— "确实没有待确认的预览"和"那个
        台账文件(或它的锁)不在",以前两者在界面上长得一模一样。调用方需要能说
        清是哪一种。
        """
        events, status = self._read_events("target_intakes.jsonl")
        return {"intakes": self._project_pending_intakes(events), "status": status}

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
        return {
            "project_id": project_id, "target": det.get("target", ""),
            "session_count": len(det.get("sessions", [])),
            "severity": sev, "findings": proj_findings[:200], "reports": reports,
        }

    def src_autopilot(self, session_id: str = "") -> Dict[str, Any]:
        """Read-only SRC autopilot/blackboard projection for the local UI.

        The projection intentionally drops result references and raw evidence;
        it exposes only candidate metadata and lease health.  Paths can be
        overridden for deployments that keep the autopilot output separate
        from the control-plane state directory.

        Engagement host runs write one blackboard per host under
        ``src-agent-runs/``, not a single global file. A missing
        ``state_dir/src-blackboard.json`` must still surface those boards —
        otherwise the 黑板 page says there is no run after every host finished.
        """
        configured = os.environ.get("PA_SRC_BLACKBOARD_PATH", "").strip()
        if configured:
            return self._src_view_from_files([(Path(configured), "")], session_id=_text(session_id, limit=128))

        wanted = _text(session_id, limit=128)
        if wanted and SESSION_ID_RE.fullmatch(wanted):
            sources = self._session_blackboard_sources(wanted)
            if sources:
                return self._src_view_from_files(sources, session_id=wanted)

        for path in (
            self.state_dir / "src-blackboard.json",
            self.state_dir / "src-autopilot" / "src-blackboard.json",
        ):
            if self._is_board_file(path):
                return self._src_view_from_files([(path, "")], session_id=wanted)

        latest = self._latest_session_with_boards()
        if latest:
            return self._src_view_from_files(
                self._session_blackboard_sources(latest), session_id=latest,
            )
        return self._empty_src_view()

    def _is_board_file(self, path: Path) -> bool:
        try:
            return path.is_file() and not path.is_symlink()
        except OSError:
            return False

    def _empty_src_view(self, *, error: str = "", session_id: str = "") -> Dict[str, Any]:
        view: Dict[str, Any] = {
            "schema": "SrcAutopilotView/v1",
            "available": False,
            "run": {},
            "candidates": [],
            "intents": [],
            "claims": [],
            "dead_ends": [],
            "hints": [],
            "session_id": session_id,
            "hosts": [],
        }
        if error:
            view["error"] = error
        return view

    def _session_blackboard_sources(self, session_id: str) -> List[Tuple[Path, str]]:
        found: List[Tuple[Path, str]] = []
        seen = set()

        def add(path: Path, host: str) -> None:
            try:
                key = str(path.resolve())
            except OSError:
                key = str(path)
            if key in seen or not self._is_board_file(path):
                return
            seen.add(key)
            found.append((path, host))

        add(self.state_dir / "src-chat" / session_id / "src-blackboard.json", "")
        try:
            from core.job_registry import JobRegistry
            records = JobRegistry(self.state_dir / "jobs").list(session_id=session_id, limit=0)
        except (OSError, RuntimeError):
            return found
        for record in records:
            host = _text((record.payload or {}).get("host") or record.target, limit=120)
            ref = str(record.summary_ref or "").strip()
            if ref:
                add(Path(ref), host)
            run_id = _text((record.payload or {}).get("run_id"), limit=80)
            if run_id:
                add(self.state_dir / "src-agent-runs" / run_id / "src-blackboard.json", host)
        return found

    def _latest_session_with_boards(self) -> str:
        latest_sid = ""
        latest_ts = -1.0
        try:
            from core.job_registry import JobRegistry
            records = JobRegistry(self.state_dir / "jobs").list(limit=0)
        except (OSError, RuntimeError):
            records = []
        for record in records:
            sid = str(record.session_id or "")
            if not sid or not SESSION_ID_RE.fullmatch(sid):
                continue
            run_id = _text((record.payload or {}).get("run_id"), limit=80)
            ref = str(record.summary_ref or "").strip()
            board: Optional[Path] = Path(ref) if ref else None
            if board is None and run_id:
                board = self.state_dir / "src-agent-runs" / run_id / "src-blackboard.json"
            if board is None or not self._is_board_file(board):
                continue
            ts = float(record.finished_at or record.started_at or record.created_at or 0.0)
            if ts >= latest_ts:
                latest_ts = ts
                latest_sid = sid
        chat_root = self.state_dir / "src-chat"
        try:
            if chat_root.is_dir():
                for sess_dir in chat_root.iterdir():
                    if not sess_dir.is_dir() or not SESSION_ID_RE.fullmatch(sess_dir.name):
                        continue
                    board = sess_dir / "src-blackboard.json"
                    if not self._is_board_file(board):
                        continue
                    try:
                        ts = board.stat().st_mtime
                    except OSError:
                        ts = 0.0
                    if ts >= latest_ts:
                        latest_ts = ts
                        latest_sid = sess_dir.name
        except OSError:
            pass
        return latest_sid

    def _src_view_from_files(
        self, sources: List[Tuple[Path, str]], *, session_id: str = "",
    ) -> Dict[str, Any]:
        snapshots: List[Tuple[Dict[str, Any], str, Dict[str, Any]]] = []
        last_error = ""
        for path, host in sources:
            if not self._is_board_file(path):
                continue
            try:
                board = SrcBlackboard(path).snapshot()
            except (FileNotFoundError, OSError, RuntimeError, TimeoutError):
                last_error = "blackboard_unavailable"
                continue
            run_path = Path(os.environ.get(
                "PA_SRC_AUTOPILOT_STATE", str(path.with_name("src-autopilot-state.json")),
            ))
            run_raw = self._read_json_file(run_path)
            run = run_raw if isinstance(run_raw, dict) else {}
            snapshots.append((board, host, run))
        if not snapshots:
            return self._empty_src_view(error=last_error, session_id=session_id)
        return self._src_view_from_snapshots(snapshots, session_id=session_id)

    def _src_view_from_snapshots(
        self,
        snapshots: List[Tuple[Dict[str, Any], str, Dict[str, Any]]],
        *,
        session_id: str = "",
    ) -> Dict[str, Any]:
        merged: Dict[str, Any] = {
            "revision": 0, "updated_at": 0, "facts": [], "intents": [],
            "claims": [], "dead_ends": [], "hints": [], "workmem": {}, "timeline": [],
        }
        run: Dict[str, Any] = {}
        hosts: List[str] = []
        for board, host, run_doc in snapshots:
            merged["revision"] = max(int(merged["revision"]), int(_number(board.get("revision"))))
            merged["updated_at"] = max(
                float(merged["updated_at"] or 0), float(_number(board.get("updated_at"))),
            )
            for key in ("facts", "intents", "claims", "dead_ends", "hints", "timeline"):
                items = board.get(key) or []
                if not isinstance(items, list):
                    continue
                rows = [item for item in items if isinstance(item, dict)]
                if key == "hints" and host:
                    tagged = []
                    for item in rows:
                        row = dict(item)
                        src = _text(row.get("source"), limit=40)
                        row["source"] = f"{host} · {src}" if src else host
                        tagged.append(row)
                    merged[key].extend(tagged)
                else:
                    merged[key].extend(rows)
            wm = board.get("workmem")
            if isinstance(wm, dict) and (wm.get("goal") or wm.get("focus") or not merged["workmem"]):
                merged["workmem"] = wm
            if run_doc:
                run = run_doc
            label = host.strip()
            if label and label not in hosts:
                hosts.append(label)
        view = self._src_view_body(merged, run)
        view["session_id"] = session_id
        view["hosts"] = hosts
        if len(hosts) > 1:
            view["run"]["run_id"] = view["run"].get("run_id") or session_id
            if not view["run"].get("stop_reason"):
                view["run"]["stop_reason"] = f"{len(hosts)} 台主机"
        return view

    def _src_view_body(self, board: Dict[str, Any], run: Dict[str, Any]) -> Dict[str, Any]:
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
                "risk_signals": [_text(item, limit=40) for item in (fact.get("risk_signals") or intent.get("risk_signals") or [])[:12]],
                "phase": _text(intent.get("phase"), limit=64),
                "status": _text(intent.get("status"), limit=24),
                "requires_human_review": intent.get("requires_human_review") is True,
                "updated_at": _number(intent.get("updated_at")),
            })
        candidates_view.sort(key=lambda item: (-int(item["priority"]), item["candidate_id"]))
        intents_view = [{
            "intent_id": _text(item.get("intent_id"), limit=80),
            "candidate_id": _text(item.get("candidate_id"), limit=80),
            "target": _text(item.get("target"), limit=300),
            "priority": max(0, min(100, int(_number(item.get("priority"))))),
            "phase": _text(item.get("phase"), limit=64),
            "status": _text(item.get("status"), limit=24),
            "requires_human_review": item.get("requires_human_review") is True,
            # DAG 依赖边 + 失败重试状态
            "depends_on": [_text(dep, limit=80) for dep in (item.get("depends_on") or [])[:12]],
            "attempts": max(0, int(_number(item.get("attempts")))),
            "max_attempts": max(1, int(_number(item.get("max_attempts")) or 3)),
            "last_error": _text(item.get("last_error"), limit=160),
            "updated_at": _number(item.get("updated_at")),
        } for item in board.get("intents", [])[:MAX_VISIBLE_ITEMS * 5] if isinstance(item, dict)]
        claims_view = [{
            "intent_id": _text(item.get("intent_id"), limit=80),
            "worker_id": _text(item.get("worker_id"), limit=120),
            "heartbeat_at": _number(item.get("heartbeat_at")),
            "lease_expires_at": _number(item.get("lease_expires_at")),
        } for item in board.get("claims", [])[:MAX_VISIBLE_ITEMS] if isinstance(item, dict)]
        dead_ends = [item for item in board.get("dead_ends", []) if isinstance(item, dict)]
        dead_ends.sort(key=lambda item: _number(item.get("created_at")))
        dead_ends_view = [{
            "intent_id": _text(item.get("intent_id"), limit=80),
            "reason": _text(item.get("reason"), limit=120),
            "detail": _text(item.get("detail"), limit=300),
            "created_at": _number(item.get("created_at")),
        } for item in dead_ends[-MAX_VISIBLE_ITEMS:]]
        hints = [item for item in board.get("hints", []) if isinstance(item, dict)]
        hints.sort(key=lambda item: _number(item.get("created_at")))
        hints_view = [{
            "intent_id": _text(item.get("intent_id"), limit=80),
            "hint": _text(item.get("hint"), limit=300),
            "source": _text(item.get("source"), limit=64),
            "created_at": _number(item.get("created_at")),
        } for item in hints[-MAX_VISIBLE_ITEMS:]]
        wm_raw = board.get("workmem") if isinstance(board.get("workmem"), dict) else {}
        workmem_view = {
            "goal": _text(wm_raw.get("goal"), limit=500),
            "focus": _text(wm_raw.get("focus"), limit=300),
            "todos": [{
                "todo_id": _text(t.get("todo_id"), limit=60),
                "text": _text(t.get("text"), limit=300),
                "status": _text(t.get("status"), limit=16),
            } for t in (wm_raw.get("todos") or [])[-MAX_VISIBLE_ITEMS:] if isinstance(t, dict)],
        }
        timeline_view = [{
            "kind": _text(item.get("kind"), limit=32),
            "summary": _text(item.get("summary"), limit=220),
            "at": _number(item.get("at")),
        } for item in (board.get("timeline") or [])[-60:] if isinstance(item, dict)]
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
            "workmem": workmem_view,
            "timeline": timeline_view,
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
