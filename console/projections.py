"""Read-only projections over durable Console state.

``ReadOnlyControlPlane`` replays goals/tasks/projects/findings from
append-only JSON/JSONL without using managers that could mutate it."""

import hmac
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
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple
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
        core.llm_pool 每次调用时读取该文件并把活跃 provider 提到 failover 队首。
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
