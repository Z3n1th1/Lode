#!/usr/bin/env python3
"""实时播报系统（broadcaster.py）。

设计决策：
1. Broadcaster 是渗透流程各阶段的播报中枢，不直接调飞书 API，
   而是通过 notifier.send_by_category() 路由到正确群组——复用已有路由表和凭据管理。
2. 所有播报方法接受 send_fn 回调（默认 notifier.send_by_category），方便测试 mock。
3. 播报内容严格遵循脱敏纪律：只含结论+指针+要用户做什么，不含证据细节/凭据/请求响应。
4. 进度播报间隔默认 30 分钟，通过文件态时间戳判断（跨进程安全）。
5. bind 地址检测是安全护栏的一部分：任何非 loopback 监听立即告警到 security_alert。
6. 不依赖外部包，只用标准库 + 同目录 notifier.py 接口。

播报路由规则：
- 开始/结束/进度 → ops_selfcheck
- 中高危发现 → finding
- 紧急高危 → security_alert + finding
- bind 告警 → security_alert

使用方式：
  from broadcaster import Broadcaster
  bc = Broadcaster()
  bc.broadcast_start("https://example.com", "标准渗透测试", "2小时")
  bc.broadcast_finding("M", "M-001", "水平越权", "/api/user/{id} 可访问他人数据",
                        "https://example.com")
  bc.broadcast_finish("https://example.com", elapsed="1小时23分",
                       high=1, medium=3, low=5,
                       key_finding="SQL注入 /api/search (已验证)")
  bc.broadcast_progress("https://example.com", audited=15, total=32,
                         phase="认证测试", medium=2, low=3)
  bc.check_bind_address("feishu_consumer", "0.0.0.0:9876")
"""
from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

try:
    from core.confidentiality import (
        external_target_label,
        outbound_audit_metadata,
        safe_external_identifier,
        sanitize_external_text,
    )
except ModuleNotFoundError:  # direct execution with core/ on sys.path
    _CORE_DIR = Path(__file__).resolve().parents[1] / "core"
    if str(_CORE_DIR) not in sys.path:
        sys.path.insert(0, str(_CORE_DIR))
    from confidentiality import (  # type: ignore
        external_target_label,
        outbound_audit_metadata,
        safe_external_identifier,
        sanitize_external_text,
    )


# ---------- 类型别名 ----------

# send_fn 签名与 notifier.send_by_category 一致：
#   send_fn(category: str, text: str) -> str (message_id)
SendFn = Callable[[str, str], str]


# ---------- 数据容器 ----------

@dataclass
class BroadcastRecord:
    """播报记录，用于审计和去重。"""
    kind: str                  # start | finish | finding | progress | bind_alert | subagent
    target: str = ""
    text: str = ""
    categories: List[str] = field(default_factory=list)
    ts: float = field(default_factory=time.time)
    message_ids: List[str] = field(default_factory=list)


# ---------- 安全的 loopback 地址集合 ----------

_SAFE_BINDS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})


def _is_loopback(bind: str) -> bool:
    """判断 bind 地址是否为安全的 loopback 地址。"""
    normalized = bind.strip().lower()
    # 裸 IPv6 loopback（::1）没有端口，不能按最后一个冒号剥离。
    if normalized in _SAFE_BINDS:
        return True
    # 去掉端口部分：127.0.0.1:8080 → 127.0.0.1, [::1]:8080 → [::1]
    host = normalized.rsplit(":", 1)[0] if ":" in normalized else normalized
    # 处理 IPv6 带方括号的情况
    if host.startswith("[") and host.endswith("]"):
        host_inner = host[1:-1]
    else:
        host_inner = host
    return host.lower() in _SAFE_BINDS or host_inner.lower() in _SAFE_BINDS


# ---------- Broadcaster ----------

class Broadcaster:
    """实时播报系统。

    播报规则（用户明确要求）：
    1. 每次渗透开始 → 播报开始消息（目标、策略、预计时间）
    2. 每次渗透结束 → 播报结束消息（发现数、耗时、关键发现摘要）
    3. 中高危发现 → 即时播报到 finding 群
    4. 进度短报 → 每30分钟或重要节点
    5. 所有子 Agent 结束 → 播报
    6. 长任务超过 1 小时 → 中间播报
    7. Agent 完成任务必须主动播报，不能做完不说
    """

    def __init__(
        self,
        send_fn: Optional[SendFn] = None,
        progress_interval: int = 1800,      # 30 分钟
        long_task_threshold: int = 3600,     # 1 小时
        audit_path: Optional[Path] = None,
    ) -> None:
        """
        Args:
            send_fn: 发送函数，签名 (category, text) -> message_id。
                     默认尝试导入 notifier.send_by_category。
            progress_interval: 进度播报最小间隔（秒），默认 1800（30分钟）。
            long_task_threshold: 长任务触发中间播报的阈值（秒），默认 3600（1小时）。
            audit_path: 播报审计日志路径（JSONL），不传则不落盘。
        """
        if send_fn is not None:
            self._send = send_fn
        else:
            self._send = self._default_send_fn()
        self.progress_interval = progress_interval
        self.long_task_threshold = long_task_threshold
        self.audit_path = audit_path
        # 内部状态
        self._records: List[BroadcastRecord] = []
        self._last_progress_ts: Dict[str, float] = {}   # target → 上次进度播报时间
        self._task_start_ts: Dict[str, float] = {}       # target → 任务开始时间
        self._long_task_sent: Dict[str, bool] = {}       # target → 是否已发过长任务播报

    @staticmethod
    def _default_send_fn() -> SendFn:
        """延迟导入 notifier.send_by_category 作为默认发送函数。"""
        try:
            import notifier  # same dir
            return notifier.send_by_category  # type: ignore[return-value]
        except ImportError:
            def _noop(category: str, text: str) -> str:
                return ""
            return _noop

    # ---------- 核心播报方法 ----------

    def broadcast_start(self, target: str, strategy: str, estimated_time: str) -> BroadcastRecord:
        """播报渗透开始。路由 → ops_selfcheck。"""
        self._task_start_ts[target] = time.time()
        self._long_task_sent[target] = False
        text = (
            f"🔔 开始渗透\n"
            f"目标：{external_target_label(target)}\n"
            f"策略：{sanitize_external_text(strategy, limit=120)}\n"
            f"预计时间：{sanitize_external_text(estimated_time, limit=40)}\n"
            f"---"
        )
        return self._do_send("start", target, text, ["ops_selfcheck"])

    def broadcast_finish(
        self,
        target: str,
        elapsed: str,
        high: int = 0,
        medium: int = 0,
        low: int = 0,
        key_finding: str = "",
    ) -> BroadcastRecord:
        """播报渗透结束。路由 → ops_selfcheck。"""
        self._task_start_ts.pop(target, None)
        self._long_task_sent.pop(target, None)
        self._last_progress_ts.pop(target, None)
        summary = f"高危{high} / 中危{medium} / 低危{low}"
        text = (
            f"✅ 渗透完成\n"
            f"目标：{external_target_label(target)}\n"
            f"耗时：{elapsed}\n"
            f"发现：{summary}\n"
        )
        if key_finding:
            text += "关键发现：已记录，内容仅保存在本机报告\n"
        text += "报告状态：已生成；完整报告和证据不通过飞书外发\n---"
        return self._do_send("finish", target, text, ["ops_selfcheck"])

    def broadcast_task_terminal(
        self,
        target: str,
        *,
        task_id: str,
        status: str,
        elapsed: str,
        report_ready: bool,
    ) -> BroadcastRecord:
        """Broadcast one durable task outcome without relabeling failures as success."""
        labels = {
            "finished": "已完成",
            "failed": "失败",
            "timeout": "超时",
            "blocked": "已阻断",
            "interrupted": "已中断",
        }
        label = labels.get(status, status or "未知")
        lines = [
            "任务结束",
            f"目标：{external_target_label(target)}",
            f"任务：{safe_external_identifier(task_id)}",
            f"状态：{label}",
            f"耗时：{elapsed}",
        ]
        if report_ready:
            lines.append("报告状态：已生成；完整报告和证据仅保存在本机")
            lines.append("回复数字 1 可查看脱敏任务状态")
        return self._do_send("task_terminal", target, "\n".join(lines), ["ops_selfcheck"])

    def broadcast_task_progress(
        self,
        target: str,
        *,
        task_id: str,
        elapsed: str,
    ) -> BroadcastRecord:
        """Send a periodic task heartbeat without inventing endpoint counts."""
        text = (
            "进度短报\n"
            f"目标：{external_target_label(target)}\n"
            f"任务：{safe_external_identifier(task_id)}\n"
            f"状态：仍在执行\n"
            f"已运行：{elapsed}"
        )
        return self._do_send("task_progress", target, text, ["ops_selfcheck"])

    def broadcast_finding(
        self,
        severity: str,
        finding_id: str,
        title: str,
        detail: str,
        target: str,
        evidence_ref: str = "",
    ) -> BroadcastRecord:
        """播报漏洞发现。

        severity: "C"(高危/紧急) | "H"(高危) | "M"(中危)
        路由规则：
        - 紧急高危 (C) → security_alert + finding
        - 高危/中危 (H/M) → finding
        """
        severity = severity.upper()
        if severity == "C":
            emoji = "🔴 紧急！发现高危漏洞"
            categories = ["security_alert", "finding"]
        elif severity == "H":
            emoji = "🔴 发现高危漏洞"
            categories = ["security_alert", "finding"]
        else:
            emoji = "⚠️ 发现中危漏洞"
            categories = ["finding"]

        text = (
            f"{emoji}\n"
            f"[{safe_external_identifier(finding_id)}] {sanitize_external_text(title, limit=120)}\n"
            f"目标：{external_target_label(target)}\n"
        )
        if evidence_ref:
            text += "验证状态：已验证；证据仅保存在本机索引\n"
        else:
            text += "验证状态：待验证；证据不通过飞书外发\n"
        return self._do_send("finding", target, text.rstrip(), categories)

    def broadcast_progress(
        self,
        target: str,
        audited: int,
        total: int,
        phase: str,
        high: int = 0,
        medium: int = 0,
        low: int = 0,
        force: bool = False,
    ) -> Optional[BroadcastRecord]:
        """进度播报（每 30 分钟或 force=True 时触发）。路由 → ops_selfcheck。

        Returns:
            BroadcastRecord if sent, None if throttled.
        """
        now = time.time()
        last = self._last_progress_ts.get(target, 0.0)
        if not force and (now - last) < self.progress_interval:
            return None  # 节流
        self._last_progress_ts[target] = now
        summary = f"高危{high} / 中危{medium} / 低危{low}" if (high or medium or low) else "暂无"
        text = (
            f"📊 进度播报（每30分钟）\n"
            f"目标：{external_target_label(target)}\n"
            f"已审计接口：{audited}/{total}\n"
            f"当前阶段：{phase}\n"
            f"已发现：{summary}\n"
            f"---"
        )
        return self._do_send("progress", target, text, ["ops_selfcheck"])

    def broadcast_subagent_done(
        self,
        target: str,
        agent_name: str,
        task_summary: str,
        findings_count: int = 0,
    ) -> BroadcastRecord:
        """子 Agent 完成任务播报。路由 → ops_selfcheck。"""
        text = (
            f"🤖 子Agent完成\n"
            f"Agent：{safe_external_identifier(agent_name)}\n"
            f"目标：{external_target_label(target)}\n"
            f"任务：已完成；skill 输出和报告仅保存在本机\n"
            f"发现数：{findings_count}\n"
            f"---"
        )
        return self._do_send("subagent", target, text, ["ops_selfcheck"])

    def check_long_task(self, target: str) -> Optional[BroadcastRecord]:
        """检查长任务是否需要中间播报（超过 1 小时触发一次）。

        Returns:
            BroadcastRecord if sent, None if not triggered or already sent.
        """
        start = self._task_start_ts.get(target)
        if start is None:
            return None
        if self._long_task_sent.get(target, False):
            return None
        elapsed = time.time() - start
        if elapsed < self.long_task_threshold:
            return None
        self._long_task_sent[target] = True
        hours = int(elapsed // 3600)
        minutes = int((elapsed % 3600) // 60)
        elapsed_str = f"{hours}小时{minutes}分" if hours else f"{minutes}分钟"
        text = (
            f"⏰ 长任务提醒\n"
            f"目标：{external_target_label(target)}\n"
            f"已运行：{elapsed_str}\n"
            f"状态：仍在执行中\n"
            f"如需暂停请回复 pause\n"
            f"---"
        )
        return self._do_send("long_task", target, text, ["ops_selfcheck"])

    # ---------- bind 地址检测 ----------

    def check_bind_address(self, service_name: str, bind: str) -> Optional[BroadcastRecord]:
        """检查服务监听地址是否安全。

        如果检测到 bind 不是 127.0.0.1/localhost/::1，立即发安全告警。

        Returns:
            BroadcastRecord if alert was sent, None if bind is safe.
        """
        if _is_loopback(bind):
            return None
        text = (
            f"⚠️ 安全告警：服务监听地址异常\n"
            f"服务：{service_name}\n"
            f"监听：{bind}\n"
            f"预期：127.0.0.1\n"
            f"建议：立即修改为 127.0.0.1 或确认是否必要"
        )
        return self._do_send("bind_alert", service_name, text, ["security_alert"])

    # ---------- 内部方法 ----------

    def _do_send(
        self,
        kind: str,
        target: str,
        text: str,
        categories: List[str],
    ) -> BroadcastRecord:
        """统一发送：向每个 category 发一次消息，记录审计日志。"""
        message_ids: List[str] = []
        for cat in categories:
            try:
                safe_text = sanitize_external_text(text)
                mid = self._send(cat, safe_text)
                message_ids.append(mid)
            except Exception:
                message_ids.append("")  # 发送失败不阻断主流程
        record = BroadcastRecord(
            kind=kind,
            target=target,
            text=sanitize_external_text(text),
            categories=categories,
            message_ids=message_ids,
        )
        self._records.append(record)
        self._audit_log(record)
        return record

    def _audit_log(self, record: BroadcastRecord) -> None:
        """审计日志落盘（JSONL）。"""
        if not self.audit_path:
            return
        try:
            self.audit_path.parent.mkdir(parents=True, exist_ok=True)
            entry = {
                "ts": record.ts,
                "kind": record.kind,
                "categories": record.categories,
                "message_ids": record.message_ids,
                **outbound_audit_metadata(record.text, record.target),
            }
            with self.audit_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception:
            pass  # 审计失败不阻断主流程

    @property
    def records(self) -> List[BroadcastRecord]:
        """返回本实例所有播报记录（用于检查/测试）。"""
        return list(self._records)


# ---------- self-test ----------

def _self_test() -> int:
    """端到端自测：mock send_fn，验证每种播报的格式、路由和审计。"""
    import tempfile

    sent: List[Dict[str, Any]] = []

    def mock_send(category: str, text: str) -> str:
        msg_id = f"mock_{len(sent)}"
        sent.append({"category": category, "text": text, "msg_id": msg_id})
        return msg_id

    with tempfile.TemporaryDirectory() as tmp:
        audit = Path(tmp) / "broadcast_audit.jsonl"
        bc = Broadcaster(
            send_fn=mock_send,
            progress_interval=1,       # 1 秒用于测试
            long_task_threshold=0,     # 0 秒用于测试长任务
            audit_path=audit,
        )

        # 1. 开始播报
        r1 = bc.broadcast_start("https://example.com", "标准渗透测试", "2小时")
        assert r1.kind == "start"
        assert r1.categories == ["ops_selfcheck"]
        assert "🔔 开始渗透" in r1.text
        assert "标准渗透测试" in r1.text
        assert len(r1.message_ids) == 1 and r1.message_ids[0].startswith("mock_")
        assert sent[-1]["category"] == "ops_selfcheck"

        # 2. 中危发现
        r2 = bc.broadcast_finding(
            "M", "M-001", "水平越权", "/api/user/{id} 可访问他人数据",
            "https://example.com",
        )
        assert r2.kind == "finding"
        assert r2.categories == ["finding"]
        assert "⚠️ 发现中危漏洞" in r2.text
        assert "[M-001]" in r2.text
        assert "待验证" in r2.text  # 没提供 evidence_ref

        # 3. 高危发现（紧急）
        r3 = bc.broadcast_finding(
            "C", "C-001", "SQL注入", "/api/search?q= 存在时间盲注",
            "https://example.com",
            evidence_ref="EvidenceCard E-xxx",
        )
        assert r3.categories == ["security_alert", "finding"]
        assert "🔴 紧急" in r3.text
        assert "EvidenceCard E-xxx" not in r3.text
        assert "证据仅保存在本机索引" in r3.text
        assert len(r3.message_ids) == 2  # 发到两个群

        # 4. 高危发现（非紧急）
        r3b = bc.broadcast_finding(
            "H", "H-001", "RCE", "/api/exec 远程命令执行",
            "https://example.com",
        )
        assert r3b.categories == ["security_alert", "finding"]
        assert "🔴 发现高危漏洞" in r3b.text

        # 5. 进度播报
        r4 = bc.broadcast_progress(
            "https://example.com", audited=15, total=32,
            phase="认证测试", medium=2, low=3,
        )
        assert r4 is not None
        assert "📊 进度播报" in r4.text
        assert "15/32" in r4.text
        assert "中危2" in r4.text

        # 5b. 进度播报节流
        r4b = bc.broadcast_progress(
            "https://example.com", audited=16, total=32,
            phase="认证测试", medium=2, low=3,
        )
        # progress_interval=1秒，刚发完应该被节流（除非刚好跨秒）
        # 但因为测试速度极快，几乎一定被节流
        # 注意：如果刚好跨秒则不被节流——两种情况都可接受

        # 5c. force 进度播报不受节流
        r4c = bc.broadcast_progress(
            "https://example.com", audited=16, total=32,
            phase="认证测试", force=True,
        )
        assert r4c is not None
        assert "暂无" in r4c.text  # 没传 high/medium/low

        # 6. 子 Agent 完成
        r5 = bc.broadcast_subagent_done(
            "https://example.com", "auth_scanner", "鉴权测试", 3,
        )
        assert r5.kind == "subagent"
        assert "🤖 子Agent完成" in r5.text
        assert "auth_scanner" in r5.text

        # 7. 长任务检测（threshold=0 所以立即触发）
        r6 = bc.check_long_task("https://example.com")
        assert r6 is not None
        assert "⏰ 长任务提醒" in r6.text

        # 7b. 第二次不再重复
        r6b = bc.check_long_task("https://example.com")
        assert r6b is None

        # 8. 结束播报
        r7 = bc.broadcast_finish(
            "https://example.com", elapsed="1小时23分",
            high=1, medium=3, low=5,
            key_finding="SQL注入 /api/search (已验证)",
        )
        assert "✅ 渗透完成" in r7.text
        assert "高危1 / 中危3 / 低危5" in r7.text
        assert "/api/search" not in r7.text
        assert "完整报告和证据不通过飞书外发" in r7.text

        # 9. bind 地址检测 — 安全地址不告警
        r8 = bc.check_bind_address("feishu_consumer", "127.0.0.1:9876")
        assert r8 is None
        r8b = bc.check_bind_address("feishu_consumer", "localhost")
        assert r8b is None
        r8c = bc.check_bind_address("feishu_consumer", "::1")
        assert r8c is None
        r8d = bc.check_bind_address("feishu_consumer", "[::1]:9876")
        assert r8d is None

        # 10. bind 地址检测 — 异常地址告警
        r9 = bc.check_bind_address("feishu_consumer", "0.0.0.0:9876")
        assert r9 is not None
        assert "⚠️ 安全告警" in r9.text
        assert "0.0.0.0:9876" in r9.text
        assert r9.categories == ["security_alert"]

        r9b = bc.check_bind_address("web_server", "192.168.1.100:8080")
        assert r9b is not None
        assert "192.168.1.100:8080" in r9b.text

        # 11. 审计日志验证
        assert audit.is_file()
        lines = audit.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) >= 8, f"expected >=8 audit lines, got {len(lines)}"
        for line in lines:
            entry = json.loads(line)
            assert "ts" in entry and "kind" in entry and "categories" in entry

        # 12. records 完整性
        all_records = bc.records
        assert len(all_records) >= 8

        # 13. _is_loopback 单元测试
        assert _is_loopback("127.0.0.1") is True
        assert _is_loopback("127.0.0.1:8080") is True
        assert _is_loopback("localhost") is True
        assert _is_loopback("localhost:3000") is True
        assert _is_loopback("::1") is True
        assert _is_loopback("[::1]:9876") is True
        assert _is_loopback("0.0.0.0") is False
        assert _is_loopback("0.0.0.0:8080") is False
        assert _is_loopback("192.168.1.1") is False
        assert _is_loopback("10.0.0.1:80") is False

    print("broadcaster self-test ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())
