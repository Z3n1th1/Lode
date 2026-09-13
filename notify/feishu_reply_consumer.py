#!/usr/bin/env python3
"""飞书入站消费进程（双向能力的另一半；出站见 feishu_client.py）。

中断续接（会话 8961db96 最后未完成项）：机器人"不理你"的根因就是没有这个
事件消费进程。本进程订阅 im.message.receive_v1，把**白名单信任用户**的指令
变成动作（人工门批准/拒绝、暂停/恢复、状态查询）。

安全设计（用户拍板 + AGENTS.md 纪律）：
- **绑定信任 user_id 白名单**（FEISHU_TRUSTED_USERS，逗号分隔 open_id/union_id）；
  白名单外消息一律忽略并记录——免 @ 也仅限白名单。
- **指令集封闭**：approve/reject/status/pause/resume/help；其他文本不触发任何动作。
- 审批指令必须有目标/card 引用；所有指令落审计 JSONL（audit/notify_commands.jsonl）。
- 通知通道只出不进的纪律在**审批指令**上例外——这是用户明确拍板的双向能力；
  但指令面最小化+白名单+审计三件套不缺。

传输层两种模式（插件化，核心逻辑与传输解耦）：
- ws：飞书 WebSocket 长连接（推荐，需 pip install lark-oapi）——无需公网端口；
- webhook：HTTP 回调（stdlib http.server）——需飞书后台配置事件回调地址，
  支持 url_verification 挑战与 verification token 校验。

用法：
  FEISHU_APP_ID=cli_xxx FEISHU_APP_SECRET=xxx FEISHU_TRUSTED_USERS=ou_xxx \
      python feishu_reply_consumer.py --mode ws --command-file <编排器指令队列文件>
  python feishu_reply_consumer.py --self-test

与编排器集成：本进程把批准的指令追加写入 --command-file（JSONL，一行一条），
orchestrator/调度层 watch 该文件执行 human_decision——文件队列是最小耦合的
跨进程接口（不引依赖、可审计、断线不丢）。
"""
from __future__ import annotations

import argparse
import hmac
import json
import os
import re
import sys
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

_CORE_DIR = Path(__file__).resolve().parents[1] / "core"
if str(_CORE_DIR) not in sys.path:
    sys.path.insert(0, str(_CORE_DIR))

from file_lock import replace_with_retry
from file_lock import AdvisoryFileLock
from confidentiality import external_target_label, sanitize_external_payload, sanitize_external_text
from goal_control import GoalControl
from goal_manager import GoalManager
from operation_profile import get_profile, resolve_request
from scoring import score_finding
from systemd_watchdog import SystemdWatchdog
from task_router import DEFAULT_STRIX_BIN, TaskManager


COMMANDS = {"approve", "reject", "status", "pause", "resume", "help"}
SEEN_CAPACITY = 5000
SEEN_TTL_SECONDS = 24 * 60 * 60
WEBHOOK_MAX_BODY_BYTES = 64 * 1024
MAX_INBOUND_TEXT_CHARS = 4096
# Approval commands carry references, never URLs, paths, or free-form code.
# Keep this deliberately compatible with task/card/finding identifiers while
# rejecting separators that could be interpreted by downstream consumers.
COMMAND_TARGET_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_FINDING_TYPE_LABELS = {
    "vertical_idor": "垂直越权",
    "horizontal_idor": "水平越权",
    "sqli": "SQL 注入",
    "rce": "远程代码执行",
    "remote_code_execution": "远程代码执行",
}
_LEADING_FEISHU_MENTION = re.compile(
    r"^(?:\s*<at\b[^>]*>.*?</at>\s*)+", re.IGNORECASE | re.DOTALL
)


def normalize_inbound_text(value: Any) -> str:
    """Remove only leading Feishu @bot markup before command parsing."""
    text = str(value or "").strip()
    return _LEADING_FEISHU_MENTION.sub("", text, count=1).strip()


@dataclass
class Command:
    action: str                      # approve|reject|status|pause|resume
    target: str = ""                 # target_id 或 card_id
    note: str = ""
    user_id: str = ""
    message_id: str = ""
    ts: float = 0.0


class SeenMessages:
    """Persisted Feishu message de-duplication with bounded TTL state."""

    def __init__(
        self,
        path: Path,
        *,
        capacity: int = SEEN_CAPACITY,
        ttl_seconds: int = SEEN_TTL_SECONDS,
    ) -> None:
        if capacity <= 0 or ttl_seconds <= 0:
            raise ValueError("seen_message_capacity_and_ttl_must_be_positive")
        self.path = Path(path)
        self.capacity = capacity
        self.ttl_seconds = ttl_seconds
        self._lock_path = self.path.with_name(self.path.name + ".lock")
        self._lock = threading.RLock()
        self._seen: Dict[str, float] = {}

    def _load_unlocked(self) -> None:
        self._seen = {}
        if not self.path.is_file():
            return
        try:
            document = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        message_ids = document.get("message_ids") if isinstance(document, dict) else None
        if not isinstance(message_ids, dict):
            return
        now = time.time()
        for message_id, timestamp in message_ids.items():
            try:
                value = float(timestamp)
            except (TypeError, ValueError):
                continue
            if now - value < self.ttl_seconds:
                self._seen[str(message_id)] = value

    def _persist_unlocked(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        staged = self.path.with_name(self.path.name + ".next")
        staged.write_text(
            json.dumps({"message_ids": self._seen}, ensure_ascii=False, sort_keys=True),
            encoding="utf-8",
        )
        replace_with_retry(staged, self.path)

    def seen_or_mark(self, message_id: str) -> bool:
        """Return whether this message was already handled, then persist new IDs."""
        message_id = message_id.strip()
        if not message_id:
            return False
        with self._lock:
            with AdvisoryFileLock(self._lock_path):
                self._load_unlocked()
                if message_id in self._seen:
                    return True
                now = time.time()
                self._seen[message_id] = now
                if len(self._seen) > self.capacity:
                    newest = sorted(self._seen.items(), key=lambda item: item[1], reverse=True)
                    self._seen = dict(newest[:self.capacity])
                self._persist_unlocked()
                return False


class _UnavailableTaskManager:
    """Keep goal creation truthful when the local Strix executable is absent."""

    def __init__(self, reason: str) -> None:
        self.reason = reason

    def submit(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        raise RuntimeError(self.reason)

    @staticmethod
    def list_tasks(limit: int = 10) -> List[Dict[str, Any]]:
        return []


class FeishuMessageSender:
    """Small token-caching adapter around the existing Feishu REST client."""

    def __init__(self, app_id: str, app_secret: str, *, refresh_seconds: int = 90 * 60) -> None:
        self.app_id = app_id
        self.app_secret = app_secret
        self.refresh_seconds = refresh_seconds
        self._token = ""
        self._expires_at = 0.0
        self._lock = threading.Lock()

    def _tenant_token(self) -> str:
        with self._lock:
            if self._token and time.monotonic() < self._expires_at:
                return self._token
            import feishu_client

            self._token = feishu_client.get_tenant_access_token(self.app_id, self.app_secret)
            self._expires_at = time.monotonic() + self.refresh_seconds
            return self._token

    def acknowledge(self, message_id: str) -> None:
        import feishu_client

        feishu_client.add_reaction(self._tenant_token(), message_id)

    def send_text(self, chat_id: str, text: str) -> None:
        import feishu_client

        feishu_client.send_text(self._tenant_token(), chat_id, sanitize_external_text(text))

    def reply_text(self, message_id: str, text: str) -> None:
        import feishu_client

        feishu_client.reply_text(self._tenant_token(), message_id, sanitize_external_text(text))

    def send_by_category(self, category: str, text: str) -> None:
        import notifier

        self.send_text(notifier.resolve_chat_id(category), text)


def build_goal_control(state_dir: Path, task_manager: Any) -> GoalControl:
    """Build the durable inbound goal state with one caller-owned runtime directory."""
    state_dir = Path(state_dir)
    return GoalControl(
        goal_manager=GoalManager(state_dir / "goals.jsonl"),
        task_manager=task_manager,
        pending_path=state_dir / "pending_profiles.jsonl",
        project_root=Path(__file__).resolve().parents[2],
    )


def build_task_manager(
    state_dir: Path,
    *,
    notify_fn: Optional[Callable[[str, str], None]] = None,
    event_fn: Optional[Callable[[str, Dict[str, Any]], None]] = None,
) -> Any:
    """Use Strix when configured; otherwise expose a truthful unavailable adapter."""
    strix_bin = os.environ.get("STRIX_BIN", DEFAULT_STRIX_BIN)
    if not Path(strix_bin).is_file():
        return _UnavailableTaskManager("strix_runner_unavailable")
    state_dir = Path(state_dir)
    return TaskManager(
        state_dir / "strix_tasks.jsonl",
        state_dir / "strix_tasks",
        strix_bin=strix_bin,
        notify_fn=notify_fn,
        event_fn=event_fn,
        scan_mode=os.environ.get("STRIX_SCAN_MODE", "quick"),
    )


def _elapsed_label(started_at: Any, finished_at: Any) -> str:
    try:
        elapsed = max(0.0, float(finished_at) - float(started_at))
    except (TypeError, ValueError):
        return "未知"
    minutes = max(1, int(elapsed // 60))
    if minutes < 60:
        return f"{minutes}分钟"
    return f"{minutes // 60}小时{minutes % 60}分"


def build_broadcast_event_handler(broadcaster: Any) -> Callable[[str, Dict[str, Any]], None]:
    """Adapt durable task lifecycle events to concise, category-routed broadcasts."""
    def handle(kind: str, task: Dict[str, Any]) -> None:
        target = str(task.get("target", ""))
        if not target:
            return
        if kind == "started":
            profile = get_profile(str(task.get("profile_name", ""))) or {}
            strategy = str(profile.get("description") or task.get("profile_name", ""))
            broadcaster.broadcast_start(target, strategy, "2小时")
            return
        if kind == "progress":
            broadcaster.broadcast_task_progress(
                target,
                task_id=str(task.get("id", "")),
                elapsed=_elapsed_label(0.0, task.get("elapsed_seconds")),
            )
            return
        if kind == "verified_finding":
            finding = task.get("finding")
            if not isinstance(finding, dict) or finding.get("verifier_status") != "confirmed":
                return
            scored = score_finding(finding)
            severity = {"medium": "M", "high": "H", "critical": "C"}.get(
                str(scored.get("severity", "")).lower()
            )
            if severity is None:
                return
            evidence_ref = str(scored.get("evidence_ref", "")).strip()
            if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", evidence_ref):
                evidence_ref = ""
            finding_id = str(scored.get("finding_id", "")).strip()
            if re.fullmatch(r"[A-Za-z0-9_.:-]{1,120}", finding_id) is None:
                return
            finding_type = str(scored.get("type", "")).strip().lower()
            broadcaster.broadcast_finding(
                severity,
                finding_id,
                _FINDING_TYPE_LABELS.get(finding_type, "已确认安全问题"),
                "已通过独立复核，详细证据保留在本地索引",
                target,
                evidence_ref=evidence_ref,
            )
            return
        if kind in {"finished", "failed", "timeout", "blocked", "interrupted"}:
            broadcaster.broadcast_task_terminal(
                target,
                task_id=str(task.get("id", "")),
                status=kind,
                elapsed=_elapsed_label(task.get("created_ts"), task.get("finished_ts")),
                report_ready=bool(task.get("report_path")),
            )
    return handle


class KnownUsers:
    """自动记录每个发信人的 open_id/chat_id（含未授信用户），去重落盘。

    解决 FEISHU_TRUSTED_USERS / FEISHU_CHAT_* 全靠人工抓值的问题：收到首条消息即
    自动建档，管理员只需打开 known_users.json 把对应 open_id/chat_id 抄进 env。
    只读追加更新，不影响白名单判定（未授信依旧 ignored_untrusted，fail-closed）。
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.users: Dict[str, Dict[str, Any]] = {}
        try:
            if self.path.is_file():
                data = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    self.users = {str(k): v for k, v in data.items() if isinstance(v, dict)}
        except (OSError, ValueError):
            self.users = {}

    def record(self, user_id: str, chat_id: str = "") -> None:
        if not user_id:
            return
        now = time.time()
        entry = self.users.get(user_id)
        if entry is None:
            entry = {"first_seen": now, "last_seen": now, "msg_count": 0, "chat_ids": []}
            self.users[user_id] = entry
        entry["last_seen"] = now
        entry["msg_count"] = int(entry.get("msg_count", 0)) + 1
        chat_ids = entry.setdefault("chat_ids", [])
        if chat_id and chat_id not in chat_ids:
            chat_ids.append(chat_id)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(self.users, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.path)


class CommandDispatcher:
    """指令解析 + 白名单 + 审计 + 落盘（与传输层无关的核心）。"""

    def __init__(self, trusted_users: List[str], command_file: Path,
                 audit_path: Optional[Path] = None, *,
                 seen_file: Optional[Path] = None,
                 goal_control: Optional[Any] = None,
                 task_manager: Optional[Any] = None,
                 ack_fn: Optional[Callable[[str], None]] = None,
                 known_users_file: Optional[Path] = None) -> None:
        self.trusted = {u.strip() for u in trusted_users if u.strip()}
        self.command_file = Path(command_file)
        self.audit_path = audit_path or self.command_file.with_suffix(".audit.jsonl")
        self.seen = SeenMessages(seen_file or self.command_file.with_suffix(".seen.json"))
        self.known_users = KnownUsers(
            known_users_file or self.command_file.with_suffix(".known_users.json"))
        self.goal_control = goal_control
        self.task_manager = task_manager
        self.ack_fn = ack_fn

    def parse_text(self, text: str) -> Optional[Command]:
        """从消息文本解析指令。形态：'approve T-001' / 'reject CARD-7 证据不足' /
        'status' / 'pause' / 'resume'。非指令返回 None。"""
        text = (text or "").strip()
        if not text:
            return None
        m = re.match(r"^(approve|reject|status|pause|resume|help)\b\s*([^\s]*)\s*(.*)$",
                     text, re.I)
        if not m:
            return None
        action = m.group(1).lower()
        if action == "help":
            action = "status"
        return Command(action=action, target=m.group(2).strip(), note=m.group(3).strip(),
                       ts=time.time())

    def handle_message(self, *, user_id: str, text: str, message_id: str = "",
                       chat_id: str = "") -> Dict[str, Any]:
        """入口：白名单校验 → 指令解析 → 落盘。返回处理结果（供传输层回复）。"""
        raw = normalize_inbound_text(text)
        audit = {
            "ts": time.time(),
            "user_id": user_id,
            "chat_id": chat_id,
            "message_id": message_id,
            "text_length": len(raw),
        }
        if len(raw) > MAX_INBOUND_TEXT_CHARS:
            audit["result"] = "rejected_message_too_large"
            self._audit(audit)
            return {"handled": False, "reason": "message_too_large"}
        try:
            self.known_users.record(user_id, chat_id)
        except OSError:
            pass  # 建档失败不阻塞指令处理
        if user_id not in self.trusted:
            audit["result"] = "ignored_untrusted"
            self._audit(audit)
            return {"handled": False, "reason": "untrusted_user"}
        try:
            if self.seen.seen_or_mark(message_id):
                audit["result"] = "duplicate"
                self._audit(audit)
                return {"handled": False, "reason": "duplicate"}
        except OSError as exc:
            audit["result"] = "seen_store_error"
            audit["error"] = type(exc).__name__
            self._audit(audit)
            return {"handled": False, "reason": "state_store_unavailable"}

        if self.ack_fn is not None and message_id:
            try:
                self.ack_fn(message_id)
                audit["ack"] = "sent"
            except Exception as exc:
                audit["ack"] = "failed"
                audit["ack_error"] = type(exc).__name__

        if self.goal_control is not None and raw.isdigit():
            result = self.goal_control.consume_numeric_reply(
                raw,
                user_id=user_id,
                chat_id=chat_id,
                message_id=message_id,
            )
            if not (result.get("state") == "ignored" and result.get("reason") == "no_pending_profile_choice"):
                audit["result"] = f"goal:{result.get('state', 'unknown')}"
                self._audit(audit)
                return self._goal_result(result)
            if raw == "1":
                audit["result"] = "task_detail"
                self._audit(audit)
                return {
                    "handled": True,
                    "channel": "detail",
                    "reply": self._task_detail_reply(chat_id),
                }

        if self.goal_control is not None and (
            raw.startswith("确认 ") or raw.startswith("confirm ")
        ):
            result = self.goal_control.consume_intake_confirmation(
                raw,
                user_id=user_id,
                chat_id=chat_id,
                message_id=message_id,
            )
            audit["channel"] = "goal"
            audit["result"] = f"goal:{result.get('state', 'unknown')}"
            self._audit(audit)
            return self._goal_result(result)

        if raw == "/goal" or raw.startswith("/goal "):
            audit["channel"] = "goal"
            result = self._accept_goal(raw[5:].strip(), user_id, chat_id, message_id)
            audit["result"] = f"goal:{result.get('state', 'unknown')}"
            self._audit(audit)
            return self._goal_result(result)

        if self.goal_control is not None and resolve_request(raw).target:
            audit["channel"] = "goal"
            result = self._accept_goal(raw, user_id, chat_id, message_id)
            audit["result"] = f"goal:{result.get('state', 'unknown')}"
            self._audit(audit)
            return self._goal_result(result)

        cmd = self.parse_text(raw)
        if cmd is None:
            audit["result"] = "ignored_not_command"
            self._audit(audit)
            return {"handled": False, "reason": "not_a_command"}
        cmd.user_id = user_id
        cmd.message_id = message_id
        if cmd.action in ("approve", "reject") and not cmd.target:
            audit["result"] = "rejected_missing_target"
            self._audit(audit)
            return {"handled": False, "reason": "approve/reject 需要目标ID或卡片ID",
                    "reply": "用法: approve <target或card_id> [备注]"}
        if cmd.action in ("approve", "reject") and not COMMAND_TARGET_RE.fullmatch(cmd.target):
            audit["result"] = "rejected_invalid_target"
            self._audit(audit)
            return {"handled": False, "reason": "invalid_command_target",
                    "reply": "目标必须是任务或卡片 ID"}
        if len(cmd.note) > 1000:
            audit["result"] = "rejected_note_too_large"
            self._audit(audit)
            return {"handled": False, "reason": "note_too_large",
                    "reply": "备注长度不能超过 1000 个字符"}
        self.command_file.parent.mkdir(parents=True, exist_ok=True)
        with self.command_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(cmd.__dict__, ensure_ascii=False) + "\n")
        audit["result"] = f"accepted:{cmd.action}"
        self._audit(audit)
        return {"handled": True, "action": cmd.action, "target": cmd.target,
                "reply": f"已受理: {cmd.action} {cmd.target}".strip()}

    def _accept_goal(
        self,
        instruction: str,
        user_id: str,
        chat_id: str,
        message_id: str,
    ) -> Dict[str, Any]:
        if self.goal_control is None:
            return {"state": "unavailable", "reason": "goal_control_unavailable"}
        if not instruction:
            return {"state": "ignored", "reason": "missing_target"}
        return self.goal_control.accept_goal_request(
            instruction,
            user_id=user_id,
            chat_id=chat_id,
            message_id=message_id,
        )

    @staticmethod
    def _goal_result(result: Dict[str, Any]) -> Dict[str, Any]:
        state = str(result.get("state", "ignored"))
        if state == "profile_choice":
            return {"handled": True, "channel": "goal", "reply": str(result.get("prompt", "请选择策略"))}
        if state == "intake_preview":
            preview = result.get("preview") if isinstance(result.get("preview"), dict) else {}
            intake_id = str(preview.get("intake_id", ""))
            options_digest = str(preview.get("options_digest", ""))
            lines = [
                "目标预检已生成",
                f"目标：{result.get('target', '')}",
                f"策略：{result.get('profile', '')}",
                "资产/指纹/情报/PoC/代理均保持关闭。",
            ]
            if intake_id and options_digest:
                lines.append(f"确认：确认 {intake_id} {options_digest}")
            else:
                lines.append("请重新提交目标预检。")
            return {"handled": True, "channel": "goal", "reply": "\n".join(lines)}
        if state == "started":
            task = result.get("task") if isinstance(result.get("task"), dict) else {}
            task_id = str(task.get("id", ""))
            lines = [
                "已开始 /goal",
                f"目标：{result.get('target', '')}",
                f"策略：{result.get('profile', '')}",
            ]
            if task_id:
                lines.append(f"任务：{task_id}")
            lines.append("进度和完成状态会主动播报。")
            return {"handled": True, "channel": "goal", "reply": "\n".join(lines)}
        if state == "starting":
            return {"handled": True, "channel": "goal", "reply": "任务正在受理，请稍候。"}
        if state == "limited_analysis":
            return {"handled": True, "channel": "goal", "reply": "已记录为限定流量分析，不创建 /goal。"}
        if state == "started_unconfirmed":
            return {"handled": True, "channel": "goal", "reply": "任务已提交，状态落盘待确认；请稍后查询。"}
        if state == "state_error":
            return {"handled": False, "channel": "goal", "reply": "状态存储异常，请稍后重试。"}
        if state == "task_error":
            return {"handled": False, "channel": "goal", "reply": "任务受理失败，请稍后重试。"}
        if state == "expired":
            return {"handled": False, "channel": "goal", "reply": "目标预检或策略选择已过期，请重新发送目标。"}
        if state == "unavailable":
            return {"handled": False, "channel": "goal", "reply": "目标控制面未启用。"}
        return {"handled": False, "channel": "goal", "reply": "未识别到可受理的测试目标。"}

    def _task_detail_reply(self, chat_id: str) -> str:
        if self.task_manager is None:
            return "暂无可展开的任务报告。"
        try:
            tasks = self.task_manager.list_tasks(limit=20)
        except Exception:
            return "任务状态暂时不可读取。"
        task = next((item for item in tasks if item.get("chat_id") == chat_id), None)
        if task is None:
            return "暂无可展开的任务报告。"
        status_labels = {
            "finished": "已完成",
            "failed": "失败",
            "timeout": "超时",
            "blocked": "已阻断",
            "running": "执行中",
            "recovery_pending": "等待恢复确认",
            "interrupted": "已中断",
        }
        status = str(task.get("status", "unknown"))
        lines = [
            f"任务详情：{task.get('id', '')}",
            f"目标：{external_target_label(task.get('target', ''))}",
            f"状态：{status_labels.get(status, status)}",
            f"策略：{task.get('profile_name', '')}",
        ]
        if task.get("goal_id"):
            lines.append(f"/goal：{task['goal_id']}")
        if task.get("report_path"):
            lines.append("报告状态：已生成；完整报告和证据仅保存在本机，不通过飞书外发。")
        return "\n".join(lines)

    def _audit(self, entry: Dict[str, Any]) -> None:
        try:
            self.audit_path.parent.mkdir(parents=True, exist_ok=True)
            with self.audit_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception:
            pass


# ---------------- webhook 传输层（stdlib） ----------------

def make_webhook_handler(
    dispatcher: CommandDispatcher,
    verification_token: str = "",
    *,
    reply_fn: Optional[Callable[[str, str], None]] = None,
):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            try:
                length = int(self.headers.get("Content-Length") or 0)
                if length < 0:
                    raise ValueError("negative_content_length")
                if length > WEBHOOK_MAX_BODY_BYTES:
                    self._reply(413, {"error": "request_too_large"})
                    return
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
            except Exception:
                self._reply(400, {"error": "bad_json"})
                return
            if not isinstance(payload, dict):
                self._reply(400, {"error": "invalid_payload"})
                return
            if not verification_token:
                self._reply(503, {"error": "verification_token_not_configured"})
                return
            header = payload.get("header")
            header = header if isinstance(header, dict) else {}
            token = header.get("token") or payload.get("token") or ""
            if not hmac.compare_digest(str(token), verification_token):
                self._reply(403, {"error": "bad_token"})
                return
            # The setup challenge is authenticated by the same verification
            # token as normal callbacks. Never reflect an unauthenticated value.
            if payload.get("type") == "url_verification":
                challenge = payload.get("challenge")
                if not isinstance(challenge, str) or not challenge:
                    self._reply(400, {"error": "invalid_challenge"})
                    return
                self._reply(200, {"challenge": challenge})
                return
            event = payload.get("event")
            if not isinstance(event, dict):
                self._reply(400, {"error": "invalid_event"})
                return
            message = event.get("message")
            sender = event.get("sender")
            if not isinstance(message, dict) or not isinstance(sender, dict):
                self._reply(400, {"error": "invalid_event"})
                return
            sender_id = sender.get("sender_id")
            sender_id = sender_id if isinstance(sender_id, dict) else {}
            user_id = sender_id.get("open_id") or sender_id.get("union_id") or ""
            message_id = str(message.get("message_id") or "").strip()
            chat_id = str(message.get("chat_id") or "").strip()
            msg_type = str(message.get("message_type") or "").strip()
            if not user_id or not message_id or not chat_id:
                self._reply(400, {"error": "invalid_message_identity"})
                return
            if msg_type != "text":
                self._reply(200, {"ok": True, "handled": False, "reason": "unsupported_message_type"})
                return
            try:
                content = json.loads(message.get("content") or "{}")
                text = content.get("text") if isinstance(content, dict) else None
            except (TypeError, ValueError, json.JSONDecodeError):
                text = None
            if not isinstance(text, str):
                self._reply(400, {"error": "invalid_text_content"})
                return
            result = dispatcher.handle_message(
                user_id=user_id, text=text,
                message_id=message_id,
                chat_id=chat_id)
            response_result = sanitize_external_payload(result)
            if reply_fn is not None and result.get("reply"):
                safe_reply = sanitize_external_text(result["reply"])
                try:
                    reply_fn(message_id, safe_reply)
                    response_result["reply_delivery"] = "sent"
                except Exception as exc:
                    response_result["reply_delivery"] = "failed"
                    response_result["reply_error"] = type(exc).__name__
            self._reply(200, {"ok": True, **response_result})

        def log_message(self, *args: Any) -> None:  # 静音默认访问日志（走审计文件）
            return

        def _reply(self, code: int, body: Dict[str, Any]) -> None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return Handler


# ---------------- ws 传输层（lark-oapi，可选依赖） ----------------

def run_ws(
    dispatcher: CommandDispatcher,
    app_id: str,
    app_secret: str,
    *,
    sender: Optional[FeishuMessageSender] = None,
) -> int:
    try:
        import lark_oapi as lark  # type: ignore
    except Exception:
        print(json.dumps({"ok": False, "error": "lark_oapi_not_installed",
                          "hint": "pip install lark-oapi 后重试；或改用 --mode webhook"}))
        return 2

    message_sender = sender or FeishuMessageSender(app_id, app_secret)

    def on_message(data: "lark.im.v1.P2ImMessageReceiveV1") -> None:
        try:
            event = data.event
            sender = event.sender.sender_id
            user_id = sender.open_id or sender.union_id or ""
            msg = event.message
            message_id = (msg.message_id or "").strip()
            chat_id = (msg.chat_id or "").strip()
            if not user_id or not message_id or not chat_id or msg.message_type != "text":
                return
            content = json.loads(msg.content or "{}")
            text = content.get("text") if isinstance(content, dict) else None
            if not isinstance(text, str):
                return
            result = dispatcher.handle_message(
                user_id=user_id or "", text=text,
                message_id=message_id, chat_id=chat_id)
            if result.get("reply"):
                message_sender.reply_text(message_id, sanitize_external_text(result["reply"]))
        except Exception:
            pass  # 单条消息处理失败不影响长连接

    handler = (lark.im.v1.P2ImMessageReceiveV1Dispatcher if hasattr(lark.im.v1, "P2ImMessageReceiveV1Dispatcher") else None)
    event_handler = (lark.EventDispatcherHandler.builder("", "")
                     .register_p2_im_message_receive_v1(on_message).build())
    ws_client = lark.ws.Client(app_id, app_secret, event_handler=event_handler,
                               log_level=lark.LogLevel.WARNING)
    watchdog = SystemdWatchdog()
    watchdog.start(status="feishu_ws_consumer_running")
    try:
        ws_client.start()
        return 0
    finally:
        watchdog.stop()


# ---------------- self-test ----------------

def _self_test() -> int:
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        disp = CommandDispatcher(["ou_trusted"], Path(tmp) / "commands.jsonl")
        # 1. 白名单内 approve
        r = disp.handle_message(user_id="ou_trusted", text="approve T-001 证据齐了", message_id="m1")
        assert r["handled"] and r["action"] == "approve" and r["target"] == "T-001", r
        # 2. 白名单外忽略
        r2 = disp.handle_message(user_id="ou_stranger", text="approve T-002")
        assert not r2["handled"] and r2["reason"] == "untrusted_user", r2
        # 3. 非指令文本忽略
        r3 = disp.handle_message(user_id="ou_trusted", text="今天天气不错")
        assert not r3["handled"], r3
        # 4. approve 缺目标被拒并提示用法
        r4 = disp.handle_message(user_id="ou_trusted", text="approve")
        assert not r4["handled"] and "用法" in r4["reply"], r4
        # 5. status/pause/resume 免目标
        for word in ("status", "pause", "resume"):
            rr = disp.handle_message(user_id="ou_trusted", text=word)
            assert rr["handled"] and rr["action"] == word, rr
        # 6. 指令与审计都落盘
        lines = (Path(tmp) / "commands.jsonl").read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 4, lines  # approve + status + pause + resume
        audit_lines = disp.audit_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(audit_lines) >= 6
        # 6.5 发信人自动建档（含未授信用户），供人工抄入 FEISHU_TRUSTED_USERS/FEISHU_CHAT_*
        known = json.loads(disp.known_users.path.read_text(encoding="utf-8"))
        assert set(known) == {"ou_trusted", "ou_stranger"}, known
        assert known["ou_stranger"]["msg_count"] == 1
        disp.handle_message(user_id="ou_trusted", text="status", chat_id="oc_room1")
        known = json.loads(disp.known_users.path.read_text(encoding="utf-8"))
        assert known["ou_trusted"]["chat_ids"] == ["oc_room1"], known
        # 7. webhook 层：url_verification 挑战响应 + 事件分发
        handler_cls = make_webhook_handler(disp, verification_token="tok123")
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        import urllib.request as ul
        port = server.server_address[1]
        def post(body: dict) -> dict:
            req = ul.Request(f"http://127.0.0.1:{port}/", data=json.dumps(body).encode(),
                             headers={"Content-Type": "application/json"})
            return json.loads(ul.urlopen(req, timeout=5).read().decode())
        challenge = post({"type": "url_verification", "token": "tok123", "challenge": "abc"})
        assert challenge.get("challenge") == "abc", challenge
        ev = post({"header": {"token": "tok123"},
                   "event": {"sender": {"sender_id": {"open_id": "ou_trusted"}},
                             "message": {"message_type": "text", "message_id": "m9",
                                         "chat_id": "oc_1",
                                         "content": json.dumps({"text": "pause"})}}})
        assert ev.get("handled") and ev.get("action") == "pause", ev
        server.shutdown()
    print("feishu_reply_consumer self-test ok")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="飞书入站消费进程（白名单指令→编排器）")
    ap.add_argument("--mode", choices=["ws", "webhook"], default="ws")
    ap.add_argument("--command-file", default="audit/notify_commands.jsonl")
    ap.add_argument("--audit-file", default="")
    ap.add_argument("--state-dir", default="", help="Goal/Task/去重运行状态目录（默认 command-file 同级）")
    ap.add_argument("--listen", default="127.0.0.1:9876", help="webhook 模式监听地址（仅本地/反代后暴露）")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return _self_test()

    trusted = os.environ.get("FEISHU_TRUSTED_USERS", "")
    if not trusted.strip():
        print(json.dumps({"ok": False, "error": "FEISHU_TRUSTED_USERS 未配置（白名单为空=拒绝启动，fail-closed）"}))
        return 2
    command_file = Path(args.command_file)
    audit_file = Path(args.audit_file) if args.audit_file else None
    state_dir = Path(args.state_dir) if args.state_dir else command_file.parent / "feishu-state"
    app_id = os.environ.get("FEISHU_APP_ID", "")
    app_secret = os.environ.get("FEISHU_APP_SECRET", "")
    if not app_id or not app_secret:
        print(json.dumps({"ok": False, "error": "FEISHU_APP_ID/FEISHU_APP_SECRET 未配置"}))
        return 2
    sender = FeishuMessageSender(app_id, app_secret)
    from broadcaster import Broadcaster

    broadcaster = Broadcaster(
        send_fn=sender.send_by_category,
        audit_path=state_dir / "broadcast_audit.jsonl",
    )
    task_manager = build_task_manager(
        state_dir,
        notify_fn=sender.send_text,
        event_fn=build_broadcast_event_handler(broadcaster),
    )
    dispatcher = CommandDispatcher(
        trusted.split(","),
        command_file,
        audit_file,
        goal_control=build_goal_control(state_dir, task_manager),
        task_manager=task_manager,
        ack_fn=sender.acknowledge,
    )

    if args.mode == "webhook":
        host, _, port = args.listen.partition(":")
        verification_token = os.environ.get("FEISHU_VERIFICATION_TOKEN", "").strip()
        if not verification_token:
            print(json.dumps({"ok": False, "error": "FEISHU_VERIFICATION_TOKEN_required_for_webhook"}))
            return 2
        try:
            alert = broadcaster.check_bind_address("feishu_consumer", args.listen)
        except Exception:
            alert = True
        if alert is not None:
            print(json.dumps({"ok": False, "error": "non_loopback_bind_rejected", "listen": args.listen}))
            return 2
        handler = make_webhook_handler(
            dispatcher,
            verification_token,
            reply_fn=sender.reply_text,
        )
        server = ThreadingHTTPServer((host, int(port or "9876")), handler)
        print(json.dumps({"ok": True, "mode": "webhook", "listen": args.listen}))
        server.serve_forever()
        return 0

    return run_ws(dispatcher, app_id, app_secret, sender=sender)


if __name__ == "__main__":
    raise SystemExit(main())
