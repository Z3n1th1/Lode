"""LLM-driven SRC agent loop: Reason → Explore → Blackboard.

Borrows Cairn's 3-phase OODA (Bootstrap/Reason/Explore) and Muteki's
cheap-planner / expensive-executor split.  Uses the existing blackboard,
scope checker, surface fetcher, and the shared LLM client (core.llm_client).

The agent NEVER performs POST, form submission, or state mutation on the
target.  All HTTP traffic is GET-only through the scope-checked fetcher
inherited from surface_discovery.  Findings are recorded as blackboard
hints/facts requiring human review through the verifier_agent framework.

Usage:
  python src_agent.py --scope scope.json --blackboard bb.json --max-cycles 10
  python agents/src_agent.py --self-test
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_CORE_DIR = _PROJECT_ROOT / "core"
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))
if str(_CORE_DIR) not in sys.path:
    sys.path.insert(0, str(_CORE_DIR))

from agents.surface_discovery import SurfaceScope, _fetch_text, _readonly_url_reason
from core.src_blackboard import SrcBlackboard, _DEP_SATISFIED

# Auto-load .env config (API keys, etc.)
try:
    import core.config  # noqa: F401
except Exception:
    pass


def _default_llm_complete(system: str, user: str, **kwargs) -> "Optional[str]":
    """LLM completion through the single shared client.

    Delegates to :func:`core.llm_client.complete_messages` so the provider pool,
    the ``prefer``/``only`` tier routing (smart Reasoner vs cheap Explorer) and
    cross-provider failover all actually apply — one transport for the whole
    product. Returns ``None`` when the pool is empty or every provider failed.
    """
    timeout = kwargs.get("timeout", 60.0)
    prefer = str(kwargs.get("prefer") or "")
    only = bool(kwargs.get("only") or False)
    try:
        from core.llm_client import complete_messages
    except Exception:  # noqa: BLE001
        return None
    try:
        message = complete_messages(
            [{"role": "system", "content": system}, {"role": "user", "content": user}],
            timeout=timeout, prefer=prefer, only=only, max_tokens=2048, temperature=0.2,
        )
    except Exception:  # noqa: BLE001
        return None
    if not message:
        return None
    text = str(message.get("content") or "").strip()
    return text or None


# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

REASONER_SYSTEM = """\
你是 SRC Reasoner，授权安全研究员的决策层。你读黑板，决定下一步挖什么。

身份：不是扫描器，是理解业务意图后找认知盲区的研究员。
思路：真价值优先 — 能打到高危/严重的才值得投入。

## 力气分配（先打更容易出高危的）
1. 未登录出他人数据 → 未授权访问
2. 换 ID 出别人数据 → IDOR
3. 认证接管 → 重置/改绑/换票
4. 注入(SQLi) / SSRF / XSS / RCE → 有差分面就打
5. JS 钥匙 → 硬编码 key、内部 API

## 规则
1. status="queued" 的 intent 是未验证的表面观察，不是漏洞。
2. dead_ends 已经试过了，不要重新建议。
3. hints 是之前探索的线索。
4. 只能被动分析（GET/HEAD），不能发 POST。
5. 优先级：高 priority + 带参数的 API > 静态路径 > 纯资源文件。
6. 每个选中的 intent 必须给出具体假设（如"res_id 参数可能存在 SQLi"）。
7. 若发现某个 intent 必须先拿到另一个 intent 的结果才能验证（例如先取到 token 再测越权），
   把它填进 depends_on —— 有未完成依赖的 intent 不会被提前执行，顺序由你决定。
8. "## Recalled Experience" 是历史记忆：[已失效] 的事实已经给过结论，[死路] 的不要重复；
   能复用历史结论就直接引用，别重新挖一遍。

## 输出（严格 JSON，无 markdown fence）
{
  "reasoning": "当前状态分析",
  "selected_intents": [
    {
      "intent_id": "I-xxxx",
      "hypothesis": "具体漏洞假设",
      "check_description": "看响应中的什么来验证",
      "expected_evidence": "什么样的响应能确认/否定",
      "depends_on": []
    }
  ],
  "should_stop": false,
  "stop_reason": ""
}

最多选 3 个。没有可挖的就 should_stop=true。\
"""

REASONER_USER_TEMPLATE = """\
Current blackboard state:

{blackboard_context}

Select up to {max_explore} queued intents to investigate. \
Output JSON only.\
"""

EXPLORER_SYSTEM = """\
你是 SRC Explorer，授权安全研究员的执行层。你分析 HTTP 响应，找真实漏洞证据。

## 分析决策树（收到响应后按序检查）

1. **Status code**
   200+JSON → 检查多余字段、内部 ID、敏感数据、换 ID 响应差异
   200+HTML → 错误信息、注释、JS 内联、debug 输出
   403 → 记录；检查 body 是否泄露信息
   500 → 高价值：可能注入、unhandled exception 泄露
   301/302 → 记录重定向目标（可能泄露内部 URL）

2. **Headers**
   Server/X-Powered-By → 版本 → CVE 关联
   X-Debug/X-Trace → debug 模式
   缺少 CSP/HSTS/X-Frame-Options → 记录

3. **Body**
   SQL 错误关键词 → SQLi 证据（SQL syntax/mysql_fetch/ORA-/pg_query/SQLSTATE）
   Stack trace → 信息泄露（路径、版本、库）
   JSON 多余字段 → 可能的 IDOR/过度暴露
   内网 IP (10.x/172.16-31.x/192.168.x) → 信息泄露
   凭据 pattern (AKIA/sk-/bearer/password=) → 敏感数据泄露

## 规则
- 每个 finding 必须引用响应中的具体内容（行号/header 名/JSON key）
- 没有证据 = 不是 finding，是猜测 → 标 dead_end
- confidence: high=直接证据 / medium=可疑 pattern 需验证 / low=弱信号
- 发现不了就说发现不了，不编造

## Sandboxed HTTP Tool
可请求额外 GET/HEAD（scope 内，最多 3 个）：
  "http_actions": [{"method": "GET", "url": "https://...", "reason": "为什么需要"}]
结果会在 follow-up 给你。不需要就省略。

## 输出（严格 JSON）
{
  "analysis": "观察到了什么",
  "findings": [
    {"type": "漏洞类型", "confidence": "high|medium|low",
     "evidence": "响应中的具体内容", "description": "说明"}
  ],
  "http_actions": [],
  "conclusion": "confirmed|dead_end|needs_human|inconclusive",
  "dead_end_reason": "为什么是 dead end",
  "suggested_next": "基于发现建议下一步"
}\
"""

EXPLORER_USER_TEMPLATE = """\
Intent: {intent_id}
Target URL: {target_url}
Phase: {phase}
Priority: {priority}
Hypothesis: {hypothesis}
Check: {check_description}

{hints_section}

HTTP Response:
  Status: {status}
  Headers (sanitized):
{headers_text}

  Body (first {body_limit} chars):
{body_text}

Analyze this response for the stated hypothesis. Output JSON only.\
"""


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*\n?(.*?)\n?\s*```", re.S)


def _parse_json_response(text: str) -> Optional[Dict[str, Any]]:
    """Robust JSON extraction from LLM output (Cairn pattern)."""
    if not text or not text.strip():
        return None
    stripped = text.strip()
    # 1. Direct parse
    try:
        obj = json.loads(stripped)
        if isinstance(obj, dict):
            return obj
    except (json.JSONDecodeError, ValueError):
        pass
    # 2. Markdown fence
    match = _JSON_FENCE_RE.search(stripped)
    if match:
        try:
            obj = json.loads(match.group(1))
            if isinstance(obj, dict):
                return obj
        except (json.JSONDecodeError, ValueError):
            pass
    # 3. First { ... } block
    start = stripped.find("{")
    if start >= 0:
        depth = 0
        for i, ch in enumerate(stripped[start:], start):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        obj = json.loads(stripped[start:i + 1])
                        if isinstance(obj, dict):
                            return obj
                    except (json.JSONDecodeError, ValueError):
                        pass
                    break
    return None


def _blackboard_to_context(snapshot: Dict[str, Any], *, max_facts: int = 50,
                           max_intents: int = 50, max_dead_ends: int = 30,
                           max_hints: int = 30) -> str:
    """Serialize blackboard snapshot to structured text for LLM context."""
    lines: List[str] = []

    facts = (snapshot.get("facts") or [])[-max_facts:]
    if facts:
        lines.append("## Facts (observed candidates)")
        for f in facts:
            # 时序事实:已失效(superseded)的候选仍保留,但必须标出来,否则 reasoner
            # 会把死路过的目标当成新观察重新投入。
            stale = " [已失效]" if f.get("valid_to") is not None else ""
            lines.append(
                f"- {f.get('fact_id', '?')}: {f.get('kind', '?')} "
                f"url={f.get('url', '?')} priority={f.get('priority', 0)} "
                f"confidence={f.get('confidence', '?')}{stale} "
                f"sources={','.join(f.get('sources') or []) or '-'}"
            )
    else:
        lines.append("## Facts: (none)")

    intents = (snapshot.get("intents") or [])[-max_intents:]
    queued = [i for i in intents if i.get("status") == "queued"]
    other = [i for i in intents if i.get("status") != "queued"]
    if queued:
        lines.append(f"\n## Queued Intents ({len(queued)} available)")
        for i in queued:
            deps = i.get("depends_on") or []
            dep_note = f" deps={','.join(str(d) for d in deps)}" if deps else ""
            lines.append(
                f"- {i.get('intent_id', '?')}: target={i.get('target', '?')} "
                f"priority={i.get('priority', 0)} phase={i.get('phase', '?')} "
                f"candidate_id={i.get('candidate_id', '?')}{dep_note}"
            )
    else:
        lines.append("\n## Queued Intents: (none)")

    if other:
        lines.append(f"\n## Other Intents ({len(other)})")
        for i in other[:20]:
            lines.append(
                f"- {i.get('intent_id', '?')}: status={i.get('status', '?')} "
                f"target={i.get('target', '?')}"
            )

    dead_ends = (snapshot.get("dead_ends") or [])[-max_dead_ends:]
    if dead_ends:
        lines.append(f"\n## Dead Ends ({len(dead_ends)})")
        for d in dead_ends:
            lines.append(
                f"- {d.get('dead_end_id', '?')}: intent={d.get('intent_id', '?')} "
                f"reason={d.get('reason', '?')}"
            )

    hints = (snapshot.get("hints") or [])[-max_hints:]
    if hints:
        lines.append(f"\n## Hints ({len(hints)})")
        for h in hints:
            lines.append(
                f"- {h.get('hint_id', '?')}: intent={h.get('intent_id', '?')} "
                f"hint={h.get('hint', '?')} source={h.get('source', '?')}"
            )

    # 时间线:压缩头 + 最近条目,让 reasoner 看到历史又不让 prompt 无限膨胀。
    head = snapshot.get("timeline_head") or {}
    head_text = str(head.get("text") or "").strip() if isinstance(head, dict) else ""
    if head_text:
        lines.append("\n## Timeline (compressed history)")
        lines.append(head_text)
    recent = [item for item in (snapshot.get("timeline") or [])[-12:] if isinstance(item, dict)]
    if recent:
        lines.append(f"\n## Recent Timeline (last {len(recent)})")
        for item in recent:
            lines.append(f"- [{item.get('kind', '?')}] {item.get('summary') or item.get('intent_id') or ''}")

    return "\n".join(lines)


_SENSITIVE_HEADERS = {"set-cookie", "cookie", "authorization", "proxy-authorization",
                      "x-api-key", "x-auth-token"}


def _sanitize_headers(headers: Dict[str, str]) -> str:
    """Strip sensitive headers before sending to LLM."""
    lines: List[str] = []
    for key, value in sorted(headers.items()):
        if key.lower() in _SENSITIVE_HEADERS:
            lines.append(f"    {key}: [redacted]")
        else:
            lines.append(f"    {key}: {value[:200]}")
    return "\n".join(lines) if lines else "    (none)"


def _fetch_for_analysis(
    url: str,
    scope: SurfaceScope,
    *,
    fetcher: Optional[Callable[..., Tuple[int, str, Dict[str, str]]]] = None,
    last_request_at: float = 0.0,
) -> Dict[str, Any]:
    """Scope-checked GET fetch for LLM analysis. Returns structured result."""
    ok, reason = scope.check_url(url)
    if not ok:
        return {"status": 0, "body": "", "headers": {}, "error": f"scope_rejected:{reason}"}
    read_reason = _readonly_url_reason(url)
    if read_reason:
        return {"status": 0, "body": "", "headers": {}, "error": f"write_blocked:{read_reason}"}
    # Rate limit
    wait = scope.delay_seconds - (time.monotonic() - last_request_at)
    if wait > 0:
        time.sleep(wait)
    get = fetcher or _fetch_text
    try:
        status, body, headers = get(url, timeout=scope.timeout_seconds, max_bytes=1_500_000)
    except Exception as exc:
        return {"status": 0, "body": "", "headers": {}, "error": str(exc)[:300]}
    return {"status": status, "body": body, "headers": headers, "error": ""}


# ---------------------------------------------------------------------------
# Agent loop
# ---------------------------------------------------------------------------

@dataclass
class AgentConfig:
    """Configuration for one SRC agent run."""
    blackboard_path: Path
    scope: SurfaceScope
    reasoner_prefer: str = "deepseek"
    explorer_prefer: str = ""
    reasoner_only: bool = False
    explorer_only: bool = False
    max_cycles: int = 20
    max_explore_per_cycle: int = 3
    worker_id: str = ""
    fetcher: Optional[Callable[..., Tuple[int, str, Dict[str, str]]]] = None
    llm_complete_fn: Optional[Callable[..., Optional[str]]] = None
    timeout: float = 60.0
    # 记忆检索:新 intent 先查 facts_as_of / 历史死路与线索,复用经验(PentAGI 的检索层)。
    enable_recall: bool = True
    recall_limit: int = 5
    # 时间线压缩:长跑时自动折叠旧条目进 head,控制 prompt 体积。
    enable_timeline_compress: bool = True
    timeline_keep: int = 40
    timeline_max_chars: int = 1600
    timeline_compress_ratio: int = 2
    # 依赖边:让 reasoner 产出的 depends_on 真正写回黑板,驱动 DAG 顺序。
    enable_dependencies: bool = True


@dataclass
class ExploreResult:
    """Outcome of exploring one intent."""
    intent_id: str
    status: str  # fact_added | dead_end | needs_human | error | deferred
    findings: List[Dict[str, Any]] = field(default_factory=list)
    dead_end_reason: str = ""
    raw_llm_response: str = ""


SUMMARY_SCHEMA = "SrcAgentRunSummary/v1"
MAX_CYCLES = 50
MAX_EXPLORE_PER_CYCLE = 5
MAX_HTTP_ACTIONS = 3
BODY_LIMIT = 15_000
_ALLOWED_METHODS = {"GET", "HEAD"}


# Transient failures (network drop, unreachable target, model unavailable,
# unparseable response) are retried before a terminal dead_end. Genuine
# "no finding" conclusions are NOT retried. Backoff is 0 so the retry happens
# inside the bounded cycle loop; the attempt cap (default 3) bounds the work.
RETRY_BACKOFF_SECONDS = 0.0
# 收尾门:reasoner 想收尾但工作记忆里还有未完成 todo 时,最多再逼它跑这么多轮
# (yaklang 的 "gate finish checkpoints on remaining todos")。
MAX_STOP_BLOCKS = 2


class SrcAgentLoop:
    """LLM-driven SRC agent: Reason → Explore → Blackboard."""

    def __init__(self, config: AgentConfig) -> None:
        config.scope.require_authorization()
        if not 1 <= config.max_cycles <= MAX_CYCLES:
            raise ValueError(f"max_cycles must be 1..{MAX_CYCLES}")
        if not 1 <= config.max_explore_per_cycle <= MAX_EXPLORE_PER_CYCLE:
            raise ValueError(f"max_explore_per_cycle must be 1..{MAX_EXPLORE_PER_CYCLE}")
        self.config = config
        self.blackboard = SrcBlackboard(config.blackboard_path)
        self._complete = config.llm_complete_fn or _default_llm_complete
        self._worker_id = config.worker_id or f"src-agent-{os.getpid()}"
        self._last_request_at = 0.0

    def run(self) -> Dict[str, Any]:
        """Main agent loop. Returns a summary dict."""
        cycles_run = 0
        total_explored = 0
        total_dead_ends = 0
        total_findings = 0
        stop_reason = ""
        errors: List[str] = []
        stop_blocks = 0

        for cycle in range(self.config.max_cycles):
            cycles_run = cycle + 1

            try:
                snapshot = self.blackboard.snapshot()
            except FileNotFoundError:
                stop_reason = "blackboard_not_found"
                break

            # 时间线压缩:用本轮快照计数折叠旧条目,避免额外一次整文件读取。
            # 压缩头下一轮才进 prompt(本轮仍能看到刚写入的原始条目)。
            self._maybe_compress_timeline(snapshot)

            if cycle == 0:
                # 工作记忆:记录本次挖掘目标(仅黑板已存在时写,不凭空建文件)。
                try:
                    domains = ", ".join(getattr(self.config.scope, "allowed_domains", ()) or ())
                    if domains:
                        self.blackboard.workmem_set(goal=f"SRC 授权挖洞:{domains}")
                except Exception:  # noqa: BLE001 - workmem is advisory, never fatal
                    pass

            queued = [i for i in (snapshot.get("intents") or [])
                      if i.get("status") == "queued"]
            if not queued:
                stop_reason = "no_queued_intents"
                break

            # Reason phase
            reason_result = self._reason(snapshot)
            if reason_result is None:
                stop_reason = "reasoner_failed"
                errors.append("reasoner_returned_none")
                break
            if reason_result.get("should_stop"):
                # 收尾门:工作记忆里还有未完成 todo 就不许收尾,最多挡 MAX_STOP_BLOCKS 次。
                open_todos = self._open_todos()
                if open_todos and stop_blocks < MAX_STOP_BLOCKS:
                    stop_blocks += 1
                    errors.append(f"stop_blocked:{len(open_todos)}_open_todos")
                    self._timeline("todo_gate", "", f"还有 {len(open_todos)} 个未完成 todo,暂不收敛")
                    continue
                stop_reason = reason_result.get("stop_reason", "reasoner_stopped")
                break

            selected = reason_result.get("selected_intents") or []
            if not selected:
                stop_reason = "reasoner_selected_nothing"
                break

            # 工作记忆:同步 reasoner 的当前推理焦点。
            try:
                reasoning = str(reason_result.get("reasoning", "")).strip()
                if reasoning:
                    self.blackboard.workmem_set(focus=reasoning[:300])
            except Exception:  # noqa: BLE001
                pass

            # 依赖边:reasoner 现在会给出 depends_on,写回黑板后 DAG 才驱动执行顺序。
            self._apply_dependencies(selected)

            # Explore phase
            for intent_id, hypothesis, check in self._plan_exploration(selected, snapshot):
                result = self._explore(intent_id, hypothesis, check, snapshot)
                if result.status == "deferred":
                    # 依赖未就绪或已被别的 worker 领走 —— 不是错误,下轮再看。
                    self._timeline("deferred", intent_id, result.dead_end_reason[:120] or "not_claimable")
                    continue
                total_explored += 1
                if result.status == "dead_end":
                    total_dead_ends += 1
                elif result.status == "fact_added":
                    total_findings += len(result.findings)
                elif result.status == "error":
                    errors.append(f"{intent_id}:{result.dead_end_reason[:100]}")

        if not stop_reason:
            stop_reason = "max_cycles"

        return {
            "schema": SUMMARY_SCHEMA,
            "worker_id": self._worker_id,
            "cycles_run": cycles_run,
            "total_explored": total_explored,
            "total_dead_ends": total_dead_ends,
            "total_findings": total_findings,
            "stop_reason": stop_reason,
            "errors": errors[:20],
        }

    def _timeline(self, kind: str, intent_id: str, summary: str) -> None:
        """Append one observation to the blackboard timeline; never fatal."""
        try:
            self.blackboard.timeline_append(kind, intent_id=intent_id, summary=summary)
        except Exception:  # noqa: BLE001 - timeline is advisory
            pass

    def _maybe_compress_timeline(self, snapshot: Optional[Mapping[str, Any]] = None) -> None:
        """Fold old timeline entries into the compressed head once it grows long.

        Keeps the reasoner prompt bounded on long runs (the folded text is still
        surfaced via ``timeline_head``), without touching recent observations.
        Pass the cycle snapshot to avoid a second full-state read.
        """
        if not self.config.enable_timeline_compress:
            return
        keep = max(1, int(self.config.timeline_keep))
        try:
            if snapshot is None:
                snapshot = self.blackboard.snapshot()
            total = len(snapshot.get("timeline") or [])
            if total > keep * max(2, int(self.config.timeline_compress_ratio)):
                self.blackboard.timeline_compress(keep=keep, max_chars=self.config.timeline_max_chars)
        except Exception:  # noqa: BLE001 - timeline is advisory
            pass

    def _apply_dependencies(self, selected: Sequence[Mapping[str, Any]]) -> None:
        """Persist the reasoner's dependency edges so the DAG gates execution."""
        if not self.config.enable_dependencies:
            return
        for spec in selected[:self.config.max_explore_per_cycle]:
            if not isinstance(spec, Mapping):
                continue
            intent_id = str(spec.get("intent_id", "")).strip()
            raw = spec.get("depends_on")
            if not intent_id or not isinstance(raw, list):
                continue
            deps = [str(item).strip() for item in raw if str(item).strip()]
            if not deps:
                continue
            try:
                intent = self.blackboard.set_dependencies(intent_id, deps)
            except Exception:  # noqa: BLE001 - edges are advisory, never fatal
                continue
            applied = [str(dep) for dep in (intent.get("depends_on") or [])]
            if applied:
                self._timeline("dependency", intent_id, f"需先完成 {', '.join(applied)}")

    @staticmethod
    def _blocking_dep(snapshot: Mapping[str, Any], intent_id: str) -> str:
        """First dependency of ``intent_id`` that is not in a satisfied state."""
        intents = snapshot.get("intents") or []
        intent = next((i for i in intents if i.get("intent_id") == intent_id), None)
        if not isinstance(intent, Mapping):
            return ""
        statuses = {str(i.get("intent_id")): i.get("status") for i in intents if isinstance(i, Mapping)}
        for dep in intent.get("depends_on") or []:
            if statuses.get(str(dep)) not in _DEP_SATISFIED:
                return str(dep)
        return ""

    def _plan_exploration(
        self,
        selected: Sequence[Mapping[str, Any]],
        snapshot: Mapping[str, Any],
    ) -> List[Tuple[str, str, str]]:
        """Resolve selected intents into (intent_id, hypothesis, check) work items.

        A selected intent whose dependency is still unmet is skipped in favour of
        exploring the blocker itself, so the DAG makes forward progress instead of
        stalling on a node that cannot be claimed yet.
        """
        planned: List[Tuple[str, str, str]] = []
        seen: set[str] = set()
        for spec in selected[:self.config.max_explore_per_cycle]:
            if not isinstance(spec, Mapping):
                continue
            intent_id = str(spec.get("intent_id", "")).strip()
            if not intent_id or intent_id in seen:
                continue
            if self.config.enable_dependencies:
                blocker = self._blocking_dep(snapshot, intent_id)
                if blocker and blocker not in seen:
                    seen.add(blocker)
                    planned.append((
                        blocker,
                        f"解锁 {intent_id} 的前置依赖",
                        "取得该依赖 intent 的结果,解除后续验证的阻塞",
                    ))
                    self._timeline("unblock", blocker, f"被 {intent_id} 依赖,优先执行")
                    continue
            seen.add(intent_id)
            hypothesis = str(spec.get("hypothesis", "")).strip() or "general security analysis"
            check = str(spec.get("check_description", "")).strip() or "look for security-relevant patterns"
            planned.append((intent_id, hypothesis, check))
        return planned[:self.config.max_explore_per_cycle]

    def _recall_context(self, snapshot: Optional[Mapping[str, Any]] = None) -> str:
        """Retrieve prior experience for the queued intents (memory reuse)."""
        if not self.config.enable_recall:
            return ""
        if snapshot is None:
            try:
                snapshot = self.blackboard.snapshot()
            except Exception:  # noqa: BLE001 - recall is advisory
                return ""
        targets = [
            str(i.get("target", "")).strip()
            for i in (snapshot.get("intents") or [])
            if isinstance(i, Mapping) and i.get("status") == "queued" and str(i.get("target", "")).strip()
        ]
        if not targets:
            return ""
        window = self.config.max_explore_per_cycle
        try:
            matches = self.blackboard.recall(
                targets[:window], limit=window, per_query=max(1, int(self.config.recall_limit)),
            )
        except Exception:  # noqa: BLE001 - recall is advisory
            return ""
        lines: List[str] = []
        for match in matches:
            facts = match.get("facts") or []
            dead_ends = match.get("dead_ends") or []
            hints = match.get("hints") or []
            if not (facts or dead_ends or hints):
                continue
            lines.append(f"- 目标 {match.get('query', '?')}:")
            for fact in facts:
                tag = "有效" if fact.get("valid") else f"已失效:{fact.get('superseded_reason') or '已推翻'}"
                lines.append(
                    f"    fact {fact.get('fact_id')} [{tag}] url={fact.get('url')} "
                    f"run={fact.get('run_id') or '-'}"
                )
            for dead_end in dead_ends:
                lines.append(f"    死路: {dead_end.get('target') or dead_end.get('intent_id')} — {dead_end.get('reason')}")
            for hint in hints:
                lines.append(f"    线索: {hint.get('hint')} (source={hint.get('source')})")
        if not lines:
            return ""
        return "## Recalled Experience (历史记忆:优先复用,别重复死路)\n" + "\n".join(lines[:24])

    def _recall_for_target(self, target: str) -> str:
        """Prior experience relevant to one explorer target (prompt addendum)."""
        if not self.config.enable_recall or not target:
            return ""
        try:
            matches = self.blackboard.recall([target], limit=1, per_query=max(1, int(self.config.recall_limit)))
        except Exception:  # noqa: BLE001 - recall is advisory
            return ""
        if not matches:
            return ""
        match = matches[0]
        lines: List[str] = []
        for fact in match.get("facts") or []:
            tag = "valid" if fact.get("valid") else "stale"
            lines.append(f"  - fact[{tag}] {fact.get('url')} (run={fact.get('run_id') or '-'})")
        for dead_end in match.get("dead_ends") or []:
            lines.append(f"  - dead_end: {dead_end.get('target') or dead_end.get('intent_id')} — {dead_end.get('reason')}")
        for hint in match.get("hints") or []:
            lines.append(f"  - hint: {hint.get('hint')}")
        if not lines:
            return ""
        return "Recalled prior experience for this target:\n" + "\n".join(lines[:10])

    def _open_todos(self) -> List[Dict[str, Any]]:
        """Unfinished working-memory todos (gates the finish checkpoint)."""
        try:
            workmem = self.blackboard.snapshot().get("workmem") or {}
        except Exception:  # noqa: BLE001 - gate is advisory if no blackboard
            return []
        return [
            t for t in (workmem.get("todos") or [])
            if isinstance(t, dict) and t.get("status") == "open"
        ]

    def _reason(self, snapshot: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Call LLM Reasoner to select intents and generate hypotheses."""
        context = _blackboard_to_context(snapshot)
        recalled = self._recall_context(snapshot)
        if recalled:
            context = f"{context}\n\n{recalled}"
        user_msg = REASONER_USER_TEMPLATE.format(
            blackboard_context=context,
            max_explore=self.config.max_explore_per_cycle,
        )
        raw = self._complete(
            REASONER_SYSTEM, user_msg,
            timeout=self.config.timeout,
            prefer=self.config.reasoner_prefer,
            only=self.config.reasoner_only,
        )
        if raw is None:
            return None
        parsed = _parse_json_response(raw)
        if parsed is None:
            return None
        return parsed

    def _explore(
        self,
        intent_id: str,
        hypothesis: str,
        check_description: str,
        snapshot: Dict[str, Any],
    ) -> ExploreResult:
        """Claim an intent, fetch the target, call LLM Explorer, write results."""
        # Find intent in snapshot
        intent = next(
            (i for i in (snapshot.get("intents") or [])
             if i.get("intent_id") == intent_id),
            None,
        )
        if intent is None:
            return ExploreResult(intent_id, "error", dead_end_reason="intent_not_found")

        target_url = str(intent.get("target", "")).strip()
        if not target_url:
            return ExploreResult(intent_id, "error", dead_end_reason="no_target_url")

        # Claim the *intended* intent: a mismatch would pair this hypothesis with
        # a different target. Unmet dependencies → deferred, not an error.
        try:
            claim = self.blackboard.claim_intent(intent_id, self._worker_id)
        except Exception as exc:
            return ExploreResult(intent_id, "error", dead_end_reason=f"claim_failed:{exc}")

        if claim is None:
            return ExploreResult(intent_id, "deferred", dead_end_reason="not_claimable")

        # 以领取到的实时 intent 为准(调用方传进来的快照可能已过期)。
        intent = claim["intent"]
        claimed_intent_id = intent["intent_id"]
        target_url = str(intent.get("target") or target_url).strip()

        # Fetch
        fetch_result = _fetch_for_analysis(
            target_url, self.config.scope,
            fetcher=self.config.fetcher,
            last_request_at=self._last_request_at,
        )
        self._last_request_at = time.monotonic()

        if fetch_result["error"]:
            # Transient network failure → requeue with retry, don't burn the intent.
            self._timeline("retry", claimed_intent_id, f"fetch_error: {fetch_result['error'][:120]}")
            self.blackboard.fail(
                claimed_intent_id, self._worker_id,
                f"fetch_error:{fetch_result['error'][:120]}",
                backoff_seconds=RETRY_BACKOFF_SECONDS,
            )
            return ExploreResult(
                claimed_intent_id, "error",
                dead_end_reason=fetch_result["error"],
            )

        if fetch_result["status"] == 0:
            self.blackboard.fail(
                claimed_intent_id, self._worker_id, "target_unreachable",
                backoff_seconds=RETRY_BACKOFF_SECONDS,
            )
            return ExploreResult(claimed_intent_id, "error", dead_end_reason="unreachable")

        try:
            self.blackboard.timeline_append(
                "fetch", intent_id=claimed_intent_id,
                summary=f"GET {target_url} → {fetch_result['status']} ({len(fetch_result['body'])}B)",
            )
        except Exception:  # noqa: BLE001 - timeline is advisory
            pass

        # Build explorer prompt
        hints_for_intent = [
            h for h in (snapshot.get("hints") or [])
            if h.get("intent_id") == claimed_intent_id
        ]
        hints_section = ""
        if hints_for_intent:
            hints_section = "Prior hints:\n" + "\n".join(
                f"  - {h.get('hint', '')}" for h in hints_for_intent[:10]
            )
        recalled = self._recall_for_target(target_url)
        if recalled:
            hints_section = f"{hints_section}\n{recalled}" if hints_section else recalled

        body_text = fetch_result["body"][:BODY_LIMIT]
        user_msg = EXPLORER_USER_TEMPLATE.format(
            intent_id=claimed_intent_id,
            target_url=target_url,
            phase=intent.get("phase", "?"),
            priority=intent.get("priority", 0),
            hypothesis=hypothesis or "general security analysis",
            check_description=check_description or "look for security-relevant patterns",
            hints_section=hints_section,
            status=fetch_result["status"],
            headers_text=_sanitize_headers(fetch_result["headers"]),
            body_limit=BODY_LIMIT,
            body_text=body_text if body_text else "(empty response body)",
        )

        raw = self._complete(
            EXPLORER_SYSTEM, user_msg,
            timeout=self.config.timeout,
            prefer=self.config.explorer_prefer,
            only=self.config.explorer_only,
        )

        if raw is None:
            # Model unavailable / rate-limited → retry rather than dead-end.
            self.blackboard.fail(
                claimed_intent_id, self._worker_id, "explorer_llm_unavailable",
                backoff_seconds=RETRY_BACKOFF_SECONDS,
            )
            return ExploreResult(
                claimed_intent_id, "error",
                dead_end_reason="explorer_llm_unavailable",
                raw_llm_response="",
            )

        parsed = _parse_json_response(raw)

        # Sandboxed HTTP action loop: LLM can request additional GET/HEAD
        # requests within scope. Max MAX_HTTP_ACTIONS per explore, max 2 rounds.
        for _action_round in range(2):
            if parsed is None:
                break
            actions = parsed.get("http_actions") or []
            if not isinstance(actions, list) or not actions:
                break
            action_results: List[str] = []
            for action in actions[:MAX_HTTP_ACTIONS]:
                if not isinstance(action, dict):
                    continue
                method = str(action.get("method", "GET")).upper().strip()
                action_url = str(action.get("url", "")).strip()
                reason = str(action.get("reason", ""))[:200]
                if method not in _ALLOWED_METHODS:
                    action_results.append(f"BLOCKED {method} {action_url}: only GET/HEAD allowed")
                    continue
                if not action_url:
                    continue
                fr = _fetch_for_analysis(
                    action_url, self.config.scope,
                    fetcher=self.config.fetcher,
                    last_request_at=self._last_request_at,
                )
                self._last_request_at = time.monotonic()
                if fr["error"]:
                    action_results.append(f"BLOCKED {method} {action_url}: {fr['error'][:120]}")
                else:
                    action_results.append(
                        f"--- {method} {action_url} (reason: {reason}) ---\n"
                        f"Status: {fr['status']}\n"
                        f"Headers:\n{_sanitize_headers(fr['headers'])}\n"
                        f"Body ({min(len(fr['body']), BODY_LIMIT)} chars):\n"
                        f"{fr['body'][:BODY_LIMIT]}"
                    )
            if not action_results:
                break
            # Follow-up LLM call with action results
            followup_msg = (
                user_msg + "\n\n--- Additional HTTP action results ---\n"
                + "\n\n".join(action_results)
                + "\n\nNow provide your final analysis JSON. Do NOT request more http_actions."
            )
            raw = self._complete(
                EXPLORER_SYSTEM, followup_msg,
                timeout=self.config.timeout,
                prefer=self.config.explorer_prefer,
                only=self.config.explorer_only,
            )
            if raw is None:
                break
            parsed = _parse_json_response(raw)

        return self._process_explorer_result(claimed_intent_id, parsed, raw)

    def _process_explorer_result(
        self,
        intent_id: str,
        parsed: Optional[Dict[str, Any]],
        raw: str,
    ) -> ExploreResult:
        """Process explorer LLM output, update blackboard accordingly."""
        if parsed is None:
            # Malformed model output is usually transient → retry.
            self.blackboard.fail(
                intent_id, self._worker_id, "explorer_response_unparseable",
                backoff_seconds=RETRY_BACKOFF_SECONDS,
            )
            return ExploreResult(
                intent_id, "error",
                dead_end_reason="unparseable_response",
                raw_llm_response=raw[:500],
            )

        conclusion = str(parsed.get("conclusion", "inconclusive")).lower()
        findings = parsed.get("findings") or []
        if not isinstance(findings, list):
            findings = []
        findings = findings[:5]  # Cap

        # Filter: only medium/high confidence with evidence
        valid_findings = [
            f for f in findings
            if isinstance(f, dict)
            and str(f.get("confidence", "")).lower() in ("medium", "high")
            and str(f.get("evidence", "")).strip()
        ]

        if conclusion == "dead_end" or (conclusion == "inconclusive" and not valid_findings):
            reason = str(parsed.get("dead_end_reason", "no_findings"))[:200]
            self.blackboard.add_dead_end(intent_id, reason)
            self.blackboard.finish(intent_id, self._worker_id, status="dead_end")
            self._timeline("dead_end", intent_id, reason)
            return ExploreResult(
                intent_id, "dead_end",
                dead_end_reason=reason,
                raw_llm_response=raw[:500],
            )

        if conclusion == "needs_human" or any(
            str(f.get("confidence", "")).lower() == "high" for f in valid_findings
        ):
            # Record findings as hints, mark as blocked for human review
            for f in valid_findings:
                hint_text = (
                    f"[{f.get('type', '?')}] confidence={f.get('confidence', '?')} "
                    f"evidence={str(f.get('evidence', ''))[:200]} "
                    f"description={str(f.get('description', ''))[:200]}"
                )
                self.blackboard.add_hint(intent_id, hint_text, source="src_agent_explorer")
            self._timeline("finding", intent_id, f"高置信发现 {len(valid_findings)} 项,待人工复核")
            self.blackboard.finish(intent_id, self._worker_id, status="blocked")
            return ExploreResult(
                intent_id, "needs_human",
                findings=valid_findings,
                raw_llm_response=raw[:500],
            )

        # Medium confidence findings: record as hints, mark completed
        for f in valid_findings:
            hint_text = (
                f"[{f.get('type', '?')}] confidence={f.get('confidence', '?')} "
                f"evidence={str(f.get('evidence', ''))[:200]} "
                f"description={str(f.get('description', ''))[:200]}"
            )
            self.blackboard.add_hint(intent_id, hint_text, source="src_agent_explorer")
        self._timeline("finding", intent_id, f"中置信线索 {len(valid_findings)} 项")
        self.blackboard.finish(intent_id, self._worker_id, status="completed")
        return ExploreResult(
            intent_id, "fact_added",
            findings=valid_findings,
            raw_llm_response=raw[:500],
        )


# ---------------------------------------------------------------------------
# Convenience entry point
# ---------------------------------------------------------------------------

def run_src_agent(
    blackboard_path: str | Path,
    scope: SurfaceScope,
    *,
    max_cycles: int = 20,
    max_explore_per_cycle: int = 3,
    reasoner_prefer: str = "deepseek",
    explorer_prefer: str = "",
    worker_id: str = "",
    fetcher: Optional[Callable] = None,
    llm_complete_fn: Optional[Callable] = None,
    timeout: float = 60.0,
    enable_recall: bool = True,
    recall_limit: int = 5,
    enable_timeline_compress: bool = True,
    timeline_keep: int = 40,
    timeline_max_chars: int = 1600,
    enable_dependencies: bool = True,
) -> Dict[str, Any]:
    """Run the SRC agent loop and return a summary."""
    config = AgentConfig(
        blackboard_path=Path(blackboard_path),
        scope=scope,
        reasoner_prefer=reasoner_prefer,
        explorer_prefer=explorer_prefer,
        max_cycles=max_cycles,
        max_explore_per_cycle=max_explore_per_cycle,
        worker_id=worker_id,
        fetcher=fetcher,
        llm_complete_fn=llm_complete_fn,
        timeout=timeout,
        enable_recall=enable_recall,
        recall_limit=recall_limit,
        enable_timeline_compress=enable_timeline_compress,
        timeline_keep=timeline_keep,
        timeline_max_chars=timeline_max_chars,
        enable_dependencies=enable_dependencies,
    )
    agent = SrcAgentLoop(config)
    return agent.run()


# ---------------------------------------------------------------------------
# Self-test (no real LLM or network)
# ---------------------------------------------------------------------------

def _self_test() -> int:
    import tempfile

    call_log: List[Tuple[str, str]] = []

    def mock_fetcher(url: str, **kwargs) -> Tuple[int, str, Dict[str, str]]:
        return 200, '{"users": [{"id": 1}]}', {"content-type": "application/json", "x-debug": "true"}

    with tempfile.TemporaryDirectory() as tmp:
        bb_path = Path(tmp) / "bb.json"
        scope = SurfaceScope(
            "test-program", "written authorization for test",
            allowed_domains=("example.com",), delay_seconds=0.0,
        )
        bb = SrcBlackboard(bb_path)
        # Seed a candidate
        bb.sync_candidates([{
            "candidate_id": "SC-test001",
            "url": "https://example.com/api/users",
            "priority": 80,
            "sources": ["openapi"],
            "next_phase": "A-passive-triage",
        }], run_id="test-run")

        # Read actual intent ID generated by sync_candidates
        snap = bb.snapshot()
        real_intent_id = snap["intents"][0]["intent_id"]

        def mock_complete(system: str, user: str, **kwargs) -> Optional[str]:
            call_log.append((system[:30], user[:30]))
            if "Reasoner" in system:
                return json.dumps({
                    "reasoning": "test cycle",
                    "selected_intents": [{
                        "intent_id": real_intent_id,
                        "hypothesis": "test IDOR",
                        "check_description": "check user ID",
                        "expected_evidence": "other user data",
                    }],
                    "should_stop": False,
                })
            if "Explorer" in system:
                return json.dumps({
                    "analysis": "found debug header",
                    "findings": [{
                        "type": "information_disclosure",
                        "confidence": "medium",
                        "evidence": "X-Debug: true header present",
                        "description": "Debug mode enabled",
                    }],
                    "conclusion": "confirmed",
                })
            return None

        summary = run_src_agent(
            bb_path, scope,
            max_cycles=2,
            fetcher=mock_fetcher,
            llm_complete_fn=mock_complete,
            worker_id="test-worker",
        )

        assert summary["schema"] == SUMMARY_SCHEMA, summary
        assert summary["total_explored"] >= 1, summary
        assert summary["stop_reason"] in ("no_queued_intents", "reasoner_selected_nothing", "max_cycles"), summary
        assert len(call_log) >= 2, f"Expected >=2 LLM calls, got {len(call_log)}"

        # Verify blackboard was updated
        snap = bb.snapshot()
        finished = [i for i in snap["intents"] if i.get("status") in ("completed", "blocked", "dead_end")]
        assert finished, "Expected at least one intent to be finished"
        hints = snap.get("hints") or []
        assert hints, "Expected at least one hint from explorer findings"

    # Test JSON parser edge cases
    assert _parse_json_response('{"a": 1}') == {"a": 1}
    assert _parse_json_response('```json\n{"b": 2}\n```') == {"b": 2}
    assert _parse_json_response('Some text\n{"c": 3}\nmore text') == {"c": 3}
    assert _parse_json_response("not json at all") is None
    assert _parse_json_response("") is None
    assert _parse_json_response(None) is None  # type: ignore[arg-type]

    print(f"src_agent self-test ok (calls={len(call_log)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())
