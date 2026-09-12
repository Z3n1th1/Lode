"""LLM-driven SRC agent loop: Reason → Explore → Blackboard.

Borrows Cairn's 3-phase OODA (Bootstrap/Reason/Explore) and Muteki's
cheap-planner / expensive-executor split.  Uses the existing blackboard,
scope checker, surface fetcher, and model_client provider pool.

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
from core.src_blackboard import SrcBlackboard

# Auto-load .env config (API keys, etc.)
try:
    import core.config  # noqa: F401
except Exception:
    pass


def _default_llm_complete(system: str, user: str, **kwargs) -> "Optional[str]":
    """Standalone LLM completion using OpenAI-compatible API.

    Reads LLM_API_KEY/LLM_BASE_URL/LLM_MODEL or LLM_PROVIDERS from env.
    Does NOT depend on core.capabilities (which may not be present).
    """
    import urllib.error
    import urllib.request as _req

    api_key = os.environ.get("LLM_API_KEY", "").strip()
    base_url = os.environ.get("LLM_BASE_URL", "https://api.deepseek.com").strip().rstrip("/")
    model = os.environ.get("LLM_MODEL", "deepseek-chat").strip()
    timeout = kwargs.get("timeout", 60.0)

    if not api_key:
        return None

    body = json.dumps({
        "model": model,
        "temperature": 0.2,
        "max_tokens": 2048,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }).encode("utf-8")

    for path in ("/v1/chat/completions", "/chat/completions"):
        url = base_url + path
        request = _req.Request(url, data=body, headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        }, method="POST")
        try:
            with _req.urlopen(request, timeout=timeout) as resp:
                payload = json.loads(resp.read(512_000))
                text = (payload.get("choices") or [{}])[0].get("message", {}).get("content", "")
                if text and text.strip():
                    return text.strip()
                return None
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 404) and path != "/chat/completions":
                continue
            return None
        except Exception:
            return None
    return None


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

## 输出（严格 JSON，无 markdown fence）
{
  "reasoning": "当前状态分析",
  "selected_intents": [
    {
      "intent_id": "I-xxxx",
      "hypothesis": "具体漏洞假设",
      "check_description": "看响应中的什么来验证",
      "expected_evidence": "什么样的响应能确认/否定"
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
            lines.append(
                f"- {f.get('fact_id', '?')}: {f.get('kind', '?')} "
                f"url={f.get('url', '?')} priority={f.get('priority', 0)} "
                f"confidence={f.get('confidence', '?')} "
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
            lines.append(
                f"- {i.get('intent_id', '?')}: target={i.get('target', '?')} "
                f"priority={i.get('priority', 0)} phase={i.get('phase', '?')} "
                f"candidate_id={i.get('candidate_id', '?')}"
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


@dataclass
class ExploreResult:
    """Outcome of exploring one intent."""
    intent_id: str
    status: str  # fact_added | dead_end | needs_human | error
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

        for cycle in range(self.config.max_cycles):
            cycles_run = cycle + 1
            try:
                snapshot = self.blackboard.snapshot()
            except FileNotFoundError:
                stop_reason = "blackboard_not_found"
                break

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

            # Explore phase
            for intent_spec in selected[:self.config.max_explore_per_cycle]:
                intent_id = str(intent_spec.get("intent_id", "")).strip()
                hypothesis = str(intent_spec.get("hypothesis", "")).strip()
                check = str(intent_spec.get("check_description", "")).strip()
                if not intent_id:
                    continue

                result = self._explore(intent_id, hypothesis, check, snapshot)
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

    def _reason(self, snapshot: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Call LLM Reasoner to select intents and generate hypotheses."""
        context = _blackboard_to_context(snapshot)
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

        # Claim
        try:
            claim = self.blackboard.claim_next(
                self._worker_id,
                phases=[str(intent.get("phase", "A-passive-triage"))],
            )
        except Exception as exc:
            return ExploreResult(intent_id, "error", dead_end_reason=f"claim_failed:{exc}")

        if claim is None:
            return ExploreResult(intent_id, "error", dead_end_reason="no_claimable_intent")

        claimed_intent_id = claim["intent"]["intent_id"]

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
