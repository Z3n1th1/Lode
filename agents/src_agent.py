"""LLM-driven SRC agent loop: Reason → Explore → Blackboard.

Borrows Cairn's 3-phase OODA (Bootstrap/Reason/Explore) and Muteki's
cheap-planner / expensive-executor split.  Uses the existing blackboard,
scope checker, surface fetcher, and the shared LLM client (core.llm_client).

The agent's HTTP surface is exactly what the authorisation document declares:
``SurfaceScope.allowed_methods`` (default GET/HEAD) plus ``allow_request_body``.
An undeclared method is refused before the request is sent, and every non-read
action is written to ``http-actions.jsonl`` in the run directory — as a full
record there, and as a fingerprint only on the blackboard.  Findings are recorded
as blackboard hints/facts requiring human review through the verifier_agent
framework.

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
import threading
import time
from concurrent.futures import ThreadPoolExecutor
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

from agents.surface_discovery import SurfaceScope, _fetch_text, _request_text
from core import action_admission
from core.rate_limit import RequestBudget, limiter_for
from core.src_blackboard import SrcBlackboard, _DEP_SATISFIED
from core import skills as _skills

# Auto-load .env config (API keys, etc.)
try:
    import core.config  # noqa: F401
except Exception:
    pass


LLM_MAX_TOKENS_ENV = "LODE_LLM_MAX_TOKENS"
# 决策层和 Explorer 的回包都是**一整条** JSON,思考一多就会被 token 上限从中间截断。
# 2026-09-21 用真实 Reasoner 提示词(system 4479 / user 10506 字符)对 deepseek-flash 实测:
#
#   max_tokens=2048  content=0 字符 / reasoning_content=7653 字符  → json.loads 报
#                    "Unterminated string" 之前的空 content 让本函数返回 None,
#                    于是 reasoner_returned_none,hunt 在第 1 圈就终止、0 个 intent 被看过。
#   max_tokens=8192  content=1901 字符 / reasoning_content=9442 字符 → 合法 JSON。
#
# 这不是新开关,是代码回补 `config/model_policy.example.yaml` 里用户已经拍过的
# `max_tokens: null`(不限制返回长度)。
DEFAULT_LLM_MAX_TOKENS = 8192


def configured_max_tokens() -> int:
    """要多少 token 才装得下"思考 + 一整条 JSON"。"""
    raw = os.environ.get(LLM_MAX_TOKENS_ENV, "").strip()
    if not raw:
        return DEFAULT_LLM_MAX_TOKENS
    try:
        return max(256, int(raw))
    except (TypeError, ValueError):
        return DEFAULT_LLM_MAX_TOKENS


# 为什么上一轮 LLM 返回了 None。``complete_messages`` 把"池子空/每家失败/超时/空
# content"折叠成同一个 None,不记下来,运行摘要里就只有一句 reasoner_returned_none,
# 只能靠一遍遍加日志去猜(2026-09-21 就是这么翻出来的)。
_LAST_LLM_ERROR = {"error": ""}


def _note_llm_failure(reason: str) -> None:
    _LAST_LLM_ERROR["error"] = str(reason)[:300]


def last_llm_error() -> str:
    """给运行摘要用:上一次 LLM 调用为什么没给出内容。"""
    return _LAST_LLM_ERROR["error"]


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
            timeout=timeout, prefer=prefer, only=only,
            max_tokens=configured_max_tokens(), temperature=0.2,
        )
    except Exception as exc:  # noqa: BLE001
        _note_llm_failure(f"{type(exc).__name__}: {str(exc)[:200]}")
        return None
    if not message:
        # ``complete_messages`` 把"池子空""每家都失败""超时"都折叠成一个 None。
        # 不把 last_error 带出来,调用方只知道"没返回",只能靠一遍遍加日志去猜。
        try:
            from core.llm_client import last_error

            _note_llm_failure(last_error() or "complete_messages returned None")
        except Exception:  # noqa: BLE001
            _note_llm_failure("complete_messages returned None")
        return None
    text = str(message.get("content") or "").strip()
    if not text:
        # 有 message 但 content 是空的:最典型的就是思考把 token 预算吃光了。
        # 这是"被截断"而不是"没答",说清楚比直接给个 None 有用得多。
        reasoning = str(message.get("reasoning_content") or "")
        if reasoning:
            _note_llm_failure(f"empty content, reasoning_content={len(reasoning)} chars "
                              f"(raise {LLM_MAX_TOKENS_ENV})")
        else:
            _note_llm_failure("empty content")
        return None
    return text


# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

# 这两个是**角色**提示,不是 doctrine。身份、真价值优先、协作姿态、响应启发式、禁止项
# 都在技能包里(`.codebuddy/skills/<pack>/SKILL.md`),运行时由 `_doctrine()` 拼在前面。
# 这里只留这个角色自己那份契约:它负责什么、输出长什么样。以前这两段各自抄了一份
# doctrine,和 SKILL.md 三份并存 —— 抄本早晚会漂,所以收成一份。
REASONER_SYSTEM = """\
你是 SRC Reasoner，这次运行的决策层。你读黑板，决定下一步挖什么。

## 规则
1. status="queued" 的 intent 是未验证的表面观察，不是漏洞。
2. dead_ends 已经试过了，不要重新建议。
3. hints 是之前探索的线索。
4. 能力面以下面这行为准 —— 不要假设更多，也不要假设更少。没被声明的方法，
   沙箱会直接拒掉，写进计划的请求只会浪费一轮:
   {capabilities}
5. 优先级：高 priority + 带参数的 API > 静态路径 > 纯资源文件。
6. 每个选中的 intent 必须给出具体假设（如"res_id 参数可能存在 SQLi"）。
7. 若发现某个 intent 必须先拿到另一个 intent 的结果才能验证（例如先取到 token 再测越权），
   把它填进 depends_on —— 有未完成依赖的 intent 不会被提前执行，顺序由你决定。
8. "## Recalled Experience" 是历史记忆：[已失效] 的事实已经给过结论，[死路] 的不要重复；
   能复用历史结论就直接引用，别重新挖一遍。

## 需要打法细节就点名要
这套系统里有一批打法卡。判断这步要用到哪本(比如看出是客户端、是联调域名、是越权形状),
把卡名填进 `read_knowledge`,它会在**下一轮**成为你上下文里的一节,然后照着它干活。
可用:`mobile`(安卓客户端面) · `url-trust`(域名/白名单信任边界) · `evidence`(怎么让发现被接受)
· `recon` · `idor` · `ssrf` · `injection` · `auth` · `chains`,以及长文知识库
(`idor-test` / `ssrf-test` / `xss-test` / http-smuggling-test …)。最多 2 个。
不确定就留空 —— 系统也会从你的分析里自己认。

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
  "read_knowledge": [],
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
你是 SRC Explorer，这次运行的执行层。你分析 HTTP 响应，找真实漏洞证据。

响应该怎么读(status / headers / body 的启发式、SQLi 与 IDOR 的识别特征)在本次运行
的作业规范里,已经拼在你的上下文前面;这里只重复一条底线:

## 规则
- 每个 finding 必须引用响应中的具体内容（行号/header 名/JSON key）
- 没有证据 = 不是 finding，是猜测 → 标 dead_end
- confidence: high=直接证据 / medium=可疑 pattern 需验证 / low=弱信号
- 发现不了就说发现不了，不编造

## Sandboxed HTTP Tool
可请求额外的方法,上限 {max_actions} 个、scope 内:
  {capabilities}
  "http_actions": [{"method": "GET", "url": "https://...", "reason": "为什么需要",
                    "body": "需要请求体时才写", "content_type": "application/x-www-form-urlencoded"}]
没被授权的方法会被拒,拒绝原因会原样回到你面前 —— 想换动词之前先看上面那行。
结果会在 follow-up 给你。不需要就省略。

## 需要打法细节就点名要
看清响应之后如果要用到某本打法(比如差分怎么设、这个弱点的证据要长什么样),把卡名填进
`read_knowledge`,它会在**下一轮**成为你上下文里的一节。可用:`mobile` · `url-trust` ·
`evidence` · `recon` · `idor` · `ssrf` · `injection` · `auth` · `chains`,以及长文知识库
(`idor-test` / `ssrf-test` / `xss-test` …)。最多 2 个;不确定就留空。

## 输出（严格 JSON）
{
  "analysis": "观察到了什么",
  "findings": [
    {"type": "漏洞类型", "confidence": "high|medium|low",
     "evidence": "响应中的具体内容", "description": "说明"}
  ],
  "http_actions": [],
  "read_knowledge": [],
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

{shape_section}{hints_section}

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


# 形状信号 → 一句具体的检查方向(信号本身来自 core/src_blackboard.hypotheses)。
#
# authz_boundary 的措辞是刻意的:这条路径上**没有**头部/凭据通道(_fetch_text 只发
# 固定的 UA/Accept),所以它问的是"未授权状态下是否已经可读",而不是"换个身份去
# 对比"。提示词不能暗示一个不存在的通道 —— 模型会照着它写出没法执行的计划。
_HYPOTHESIS_BRIEF = {
    "idor": "对象引用可枚举 —— 换一个同形状的对象,看是否回的是别人的数据",
    "injection": "带搜索/过滤/排序参数 —— 看回显与报错,判断能否注入",
    "ssrf": "参数看起来是 URL/目标地址 —— 看服务端是否会替你去取",
    "path_traversal": "参数看起来是文件路径 —— 看能否读到预期之外的文件",
    "graphql": "GraphQL 端点 —— 看内省是否开放、字段级授权是否逐字段校验",
    "authz_boundary": "路径位于授权边界上 —— 只判断它在**未授权**状态下是否已经可读"
                      "(不做凭据重放,这条路径没有凭据通道)",
}


def _shape_signals_section(names: Any, url: str = "") -> str:
    """The Explorer's 'what to look for' block, or '' when the shape says nothing.

    Empty is a real answer: a static asset with no parameters gives the Explorer no
    prior, and inventing one would be worse than letting the model read the response.

    The old ``state_changing_endpoint`` note is gone with the branch that produced it:
    a state-changing-looking URL is now refused by the gate before the Explorer runs,
    so there is no reachable case in which a "this one is a change, not a read" warning
    has to be shown. See ``core.action_admission``.

    ``url`` is kept in the signature — callers pass it, and the next shape prior that
    needs it should not have to re-thread it.
    """
    del url
    wanted = [str(name) for name in (names or []) if str(name) in _HYPOTHESIS_BRIEF]
    notes: List[str] = [f"  - {name}: {_HYPOTHESIS_BRIEF[name]}" for name in wanted]
    if not notes:
        return ""
    return "Shape signals (from the URL, not a claim):\n" + "\n".join(notes) + "\n\n"


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
                           max_intents: int = 50, max_other_intents: int = 20,
                           max_dead_ends: int = 30,
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

    # 先分再截,而且要在**完整**列表上分。
    #
    # 黑板里 intents 是按优先级降序存的,所以老写法 ``[-max_intents:]`` 每次都在
    # 取分数最低的那一段:候选多于 50 个时,分数最高的那批从来没进过 reasoner 的
    # 上下文,模型看不到最该看的 intent。facts 不同 —— 它是插入序,取尾部才是"最近
    # 的 N 条",别跟着一起改。
    intents = [i for i in (snapshot.get("intents") or []) if isinstance(i, dict)]
    queued_all = [i for i in intents if i.get("status") == "queued"]
    queued = queued_all[:max_intents]
    other_all = [i for i in intents if i.get("status") != "queued"]
    other = other_all[:max_other_intents]
    if queued:
        lines.append(f"\n## Queued Intents ({len(queued_all)} available)")
        for i in queued:
            deps = i.get("depends_on") or []
            dep_note = f" deps={','.join(str(d) for d in deps)}" if deps else ""
            shapes = i.get("hypotheses") or []
            shape_note = f" shapes={','.join(str(s) for s in shapes)}" if shapes else ""
            lines.append(
                f"- {i.get('intent_id', '?')}: target={i.get('target', '?')} "
                f"priority={i.get('priority', 0)} phase={i.get('phase', '?')} "
                f"candidate_id={i.get('candidate_id', '?')}{shape_note}{dep_note}"
            )
    else:
        lines.append("\n## Queued Intents: (none)")

    if other:
        lines.append(f"\n## Other Intents ({len(other_all)})")
        for i in other:
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


def _refused(error: str, method: str) -> Dict[str, Any]:
    return {"status": 0, "body": "", "headers": {}, "error": error, "method": method}


#: 这些拒绝是**终态**:再试一次是同一个结果。URL 不在范围里、方法没被声明、请求形状
#: 过不了治理、分类器不可用、额度用完 —— 它们都不随时间改变。
#:
#: 和网络抖动分开很重要。以前任何 error 都走同一条 ``fail(backoff_seconds=...)``,于是
#: 一个注定过不了闸门的候选会被重排队到 ``DEFAULT_MAX_ATTEMPTS``(3)次,每次都重新规划
#: 一遍、烧掉一次 LLM 调用,还占着圈数。治理结论不该被当成"可能只是这次运气不好"。
TERMINAL_REFUSAL_PREFIXES = (
    "scope_rejected:",
    "method_not_allowed:",
    "body_not_allowed",
    "request_budget_exhausted",
    "unknown_operation_selector",
    "state_changing_endpoint",
    action_admission.DESTRUCTIVE_METHOD,
    action_admission.NOT_IN_PROBE_TIER,
    action_admission.NOT_PROVEN,
    action_admission.CLASSIFIER_UNAVAILABLE,
    "mutating_request_refused:",
)


def _is_terminal_refusal(error: str) -> bool:
    text = str(error or "")
    return any(text.startswith(prefix) for prefix in TERMINAL_REFUSAL_PREFIXES)


def _sha12(value: str) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8", errors="replace")).hexdigest()[:12]


def _fingerprint(body: str, content_type: str = "") -> str:
    """A body's identity without its contents — what the blackboard is allowed to keep."""
    if not body:
        return "empty"
    stamp = f"sha256={_sha12(body)} len={len(body)}"
    return f"{stamp} type={content_type}" if content_type else stamp


def _fetch_for_analysis(
    url: str,
    scope: SurfaceScope,
    *,
    method: str = "GET",
    body: str = "",
    content_type: str = "",
    fetcher: Optional[Callable[..., Tuple[int, str, Dict[str, str]]]] = None,
    requester: Optional[Callable[..., Tuple[int, str, Dict[str, str]]]] = None,
    budget: Optional[RequestBudget] = None,
) -> Dict[str, Any]:
    """Scope-checked request for LLM analysis. Returns structured result.

    The order of the gates is the whole point, and so is the fact that there is only
    one copy of them: URL in scope → *destructive verbs refused outright* → method
    declared by the authorisation document → body declared → :mod:`core.action_admission`
    → request budget → send. A caller that skips this function skips all of them.

    The admission gate is the one that reads the document *and* the request shape. It
    refuses any state-changing-looking URL unconditionally, and lets a non-read method
    through only when the request positively proves it is a read. There is no
    "wait for a human" branch, because ``guardrails.tools.human_gate`` is hard-blocked
    and no local path can approve anything — see ``core.action_admission``.

    ``method`` is echoed back in the result: the timeline and the prompt both report
    what ran, and an audit line that says "GET" for a request that was not a GET is
    worse than no audit line.
    """
    verb = str(method or "GET").strip().upper() or "GET"
    ok, reason = scope.check_url(url)
    if not ok:
        return _refused(f"scope_rejected:{reason}", verb)
    if verb in action_admission.DESTRUCTIVE_METHODS:
        # Ahead of the declaration check on purpose: DELETE is never legal, and the
        # audit should say "destructive method" rather than "you didn't declare it".
        return _refused(action_admission.DESTRUCTIVE_METHOD, verb)
    if not scope.allows_method(verb):
        # 方法准入:授权文档没写这个动词,就是没授权。以前"只读"写在源码里,
        # 文档从来没说过能做什么。
        return _refused(f"method_not_allowed:{verb}", verb)
    payload = body.encode("utf-8") if isinstance(body, str) and body else None
    if payload and not scope.allow_request_body:
        return _refused("body_not_allowed", verb)
    # 第五道闸门:这次的请求形状是不是只读。读了 URL、读了 body 容器、读了方法,然后
    # 要么放行要么给出一个操作员能照着改的理由。**没有"待人工确认"这一档** ——
    # guardrails 的人工门恒为 hard_blocked,本地没有任何可达的放行路径,所以"需要人
    # 判断"在这里就等于"拒绝",审计里会写明这一点。
    verdict = action_admission.admit(method=verb, url=url, body=body or "",
                                     content_type=content_type)
    if not verdict.allowed:
        return _refused(verdict.reason, verb)
    # 计数点在这里:治理拒掉的请求不消耗额度,而额度用完的运行立刻返回 —— 不然它会先
    # 睡在一个令牌上、睡醒了才发现没得发。速率盖住"多快",这个盖住"多少"。
    if budget is not None and not budget.spend():
        return _refused("request_budget_exhausted", verb)
    # 限速交给全局桶(见 core/rate_limit)。以前是调用方传 last_request_at 进来、
    # 自己 sleep —— 那份"间隔"是每个 agent 运行各一份,并发起来就是 N 倍速率。
    limiter = limiter_for(scope)
    if limiter is not None:
        limiter.acquire(url)
    try:
        if verb == "GET":
            # GET 继续走注入的 fetcher(签名一个字没变,九个测试依赖它)。
            send = fetcher or _fetch_text
            status, text, headers = send(url, timeout=scope.timeout_seconds, max_bytes=1_500_000)
        else:
            # 其余方法走第二条接缝 —— 不往老签名上加参数,就不必改任何既有 fetcher。
            send = requester or _request_text
            status, text, headers = send(verb, url, timeout=scope.timeout_seconds,
                                         max_bytes=1_500_000, body=payload,
                                         content_type=content_type)
    except Exception as exc:
        return _refused(str(exc)[:300], verb)
    return {"status": status, "body": text, "headers": headers, "error": "", "method": verb}


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
    # 一个 cycle 里同时探几个 intent。1 = 老行为(串行)。每轮的墙钟大头是
    # Explorer 那次 LLM 调用,所以这条直接决定单个 target 跑多快。
    max_parallel_explore: int = 3
    worker_id: str = ""
    fetcher: Optional[Callable[..., Tuple[int, str, Dict[str, str]]]] = None
    # 非 GET 的第二条接缝。老签名上加参数会逼所有既有注入方一起改,所以 GET 走
    # fetcher(签名不变)、其余方法走这里。
    requester: Optional[Callable[..., Tuple[int, str, Dict[str, str]]]] = None
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
    # 知识激活:用哪个技能包,以及开局先激活哪几篇(jobs.py 从操作员那句话推)。
    skill_pack: str = "pentest"
    knowledge_seed: Tuple[str, ...] = ()
    # 这一轮还能发多少请求(见 core.rate_limit.RequestBudget)。None = 不计数,给
    # 单测和库里调用用;生产路径一律带一份 —— 平台红线要求"最小化",而在这之前
    # 根本没有任何计数器。
    request_budget: Optional[RequestBudget] = None


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
MAX_PARALLEL_EXPLORE = 5
MAX_HTTP_ACTIONS = 3
BODY_LIMIT = 15_000
# 非读动作的完整审计留在 run 目录里,黑板/时间线只留指纹 —— 时间线的去敏只有
# core/src_blackboard.py 那个弱正则,不该拿它当"body 不会外泄"的保证。
HTTP_ACTION_LOG = "http-actions.jsonl"


# Transient failures (network drop, unreachable target, model unavailable,
# unparseable response) are retried before a terminal dead_end. Genuine
# "no finding" conclusions are NOT retried. Backoff is 0 so the retry happens
# inside the bounded cycle loop; the attempt cap (default 3) bounds the work.
RETRY_BACKOFF_SECONDS = 0.0
# 收尾门:reasoner 想收尾但工作记忆里还有未完成 todo 时,最多再逼它跑这么多轮
# (yaklang 的 "gate finish checkpoints on remaining todos")。
MAX_STOP_BLOCKS = 2

# -- knowledge activation ----------------------------------------------------
#
# "MoE": a signal activates an expert, and the activated expert specialises the rest of
# the work. The hunt used to run on the two hardcoded prompts below and never touched
# the skill pack at all — the distilled playbooks only reached *conversation* turns.
#
# Two things trigger activation, and both feed the same set:
#   1. the harness scans the hypothesis / response for a shape it recognises
#      (core.skills.signal_modules), and
#   2. the model names a card outright in its JSON output.
# Either way a card is loaded ONCE and then rides in the system prompt for the rest of
# the run. That is why the per-card cap here is far tighter than the 12k the
# read_knowledge tool allows: this text is paid for on EVERY subsequent cycle, not once.
KNOWLEDGE_MAX_ACTIVE = 4
KNOWLEDGE_CARD_CHARS = 2_500
KNOWLEDGE_TOTAL_CHARS = 6_000


def record_http_action(blackboard_path: str | Path, *, url: str, body: str = "",
                       content_type: str = "", result: Mapping[str, Any],
                       reason: str = "", kind: str = "action") -> None:
    """Append one request to the run's ``http-actions.jsonl``. Never raises.

    Red line 10 (测试全程留痕) makes this the record of what actually left the process,
    so **every** egress has to come through here. It used to be a method on
    :class:`SrcAgentLoop` called from exactly one place — the LLM's ``http_actions``
    loop — which left two holes: the intent's own first fetch was written only to the
    timeline, and the Console chat's ``fetch_url`` tool was not written anywhere at all.

    Module-level rather than a method because the chat path has no loop to hang it off.

    ``decision`` is derived, not passed: a row carrying an ``error`` was refused, one
    without it went out. ``kind`` says which door it came through
    (``intent_fetch`` | ``action`` | ``chat_fetch``).

    The request body is written in full **only here** — it is our own probe, and this is
    what makes the log auditable. The response is a fingerprint: that is third-party
    data, and 红线 6 forbids keeping it.
    """
    method = str(result.get("method") or "GET")
    error = str(result.get("error") or "")
    headers = result.get("headers") or {}
    response_body = str(result.get("body") or "")
    record = {
        "at": time.time(),
        "kind": kind,
        "decision": f"refused:{error}" if error else "allowed",
        "method": method,
        "url": url,
        "reason": reason,
        "error": error,
        "status": result.get("status"),
        "request": {"content_type": content_type, "length": len(body or ""),
                    "sha256_12": _sha12(body or "")},
        "response": {"content_type": str(headers.get("content-type") or ""),
                     "length": len(response_body), "sha256_12": _sha12(response_body)},
        # 只在这一个文件里留全文;黑板/事件流里只有指纹。
        "request_body": body or "",
    }
    try:
        path = Path(blackboard_path).parent / HTTP_ACTION_LOG
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass


class SrcAgentLoop:
    """LLM-driven SRC agent: Reason → Explore → Blackboard."""

    def __init__(self, config: AgentConfig) -> None:
        config.scope.require_authorization()
        # Reasoner 返回 None 有两种完全不同的原因(LLM 没给出内容 / 给的内容不是
        # JSON),以前两种都报成同一句 reasoner_returned_none。分开记,摘要里才看得懂。
        self._last_reason_error = ""
        if not 1 <= config.max_cycles <= MAX_CYCLES:
            raise ValueError(f"max_cycles must be 1..{MAX_CYCLES}")
        if not 1 <= config.max_explore_per_cycle <= MAX_EXPLORE_PER_CYCLE:
            raise ValueError(f"max_explore_per_cycle must be 1..{MAX_EXPLORE_PER_CYCLE}")
        if not 1 <= config.max_parallel_explore <= MAX_PARALLEL_EXPLORE:
            raise ValueError(f"max_parallel_explore must be 1..{MAX_PARALLEL_EXPLORE}")
        self.config = config
        self.blackboard = SrcBlackboard(config.blackboard_path)
        self._complete = config.llm_complete_fn or _default_llm_complete
        self._worker_id = config.worker_id or f"src-agent-{os.getpid()}"
        # 已激活的打法:name -> 正文。只在第一次激活时读盘,之后每轮复用。
        self._activated: Dict[str, str] = {}
        self._activation_log: List[Dict[str, Any]] = []
        self._activation_lock = threading.Lock()
        # 作业规范(技能包 dispatcher)只读一次,之后每轮复用。
        self._doctrine_text: Optional[str] = None
        if config.knowledge_seed:
            self.activate(config.knowledge_seed, source="seed")

    # ------------------------------------------------------------ activation
    #
    # What has been activated is injected into every later system prompt, so the cap is
    # on *chars* as much as on count: a card that is paid for on every cycle has to earn
    # its place. Nothing here is loaded up front except the seed.

    def activate(self, names: Sequence[str], *, source: str) -> List[str]:
        """Load playbooks by name, once each. Returns the ones newly activated.

        并发起 explore 之后这个方法会被多个线程同时进:它是"先查再写"的
        (``name in self._activated`` 之后再 ``self._activated[name] = text``),
        没有锁的话同一篇打法会被激活两次、日志里出两条、字符预算也可能被冲过。
        加锁比把状态拆开便宜,而且这一层本来就不在热路径上。
        """
        added: List[str] = []
        with self._activation_lock:
            for raw in names or ():
                name = str(raw or "").strip().removesuffix(".md")
                if not name or name in self._activated:
                    continue
                if len(self._activated) >= KNOWLEDGE_MAX_ACTIVE:
                    break
                budget = KNOWLEDGE_TOTAL_CHARS - sum(len(t) for t in self._activated.values())
                if budget < 200:
                    break
                got = _skills.read_knowledge(name, limit=min(KNOWLEDGE_CARD_CHARS, budget))
                text = str(got.get("text") or "")
                if not text:
                    continue
                self._activated[name] = text
                self._activation_log.append({
                    "name": name, "source": source, "library": got.get("source"),
                    "chars": got.get("chars"), "truncated": bool(got.get("truncated")),
                })
                added.append(name)
        return added

    def activate_from_signals(self, *texts: str, source: str) -> List[str]:
        """Activate whatever shape the harness recognises in ``texts``."""
        blob = "\n".join(t for t in texts if t)
        if not blob:
            return []
        names = _skills.signal_modules(blob, limit=KNOWLEDGE_MAX_ACTIVE,
                                       pack=self.config.skill_pack)
        return self.activate(names, source=source)

    def _activated_section(self) -> str:
        # 先取快照再渲染:并发 explore 时另一个线程可能正在往 self._activated 里
        # 加条目,直接迭代 items() 会 RuntimeError: dictionary changed size。
        with self._activation_lock:
            items = list(self._activated.items())
        if not items:
            return ""
        parts = ["## 已激活的打法（这次运行已经加载,直接照着做,不要重新问一遍）"]
        for name, text in items:
            parts.append(f"### {name}\n{text}")
        return "\n\n".join(parts)

    def _doctrine(self) -> str:
        """The pack's dispatcher — the single copy of identity, priorities and rules."""
        if self._doctrine_text is None:
            self._doctrine_text = _skills.compose_prompt(self.config.skill_pack)
        return self._doctrine_text

    def _system(self, base: str, *, capabilities: bool = True) -> str:
        """作业规范 + 角色契约 + 已激活的打法。

        这三段合起来才是模型看到的 system prompt:doctrine 只有一份(技能包),角色只带
        自己那份输出契约,激活的卡是这一趟临时加上去的专家。

        ``capabilities`` 默认开:角色契约里的 ``{capabilities}`` 占位符换成**这份授权
        文档**说的能力行。用 replace 而不是 ``.format()`` —— 这两段里有 JSON 示例,
        ``.format()`` 会当场把花括号吃掉。

        关掉它(base 里没有占位符时本来也是空操作)是给不希望 prompt 依赖 scope 的
        调用方留的;默认行为是"模型看到的 = 沙箱会执行的",两边同一份来源。
        """
        if capabilities:
            base = base.replace("{capabilities}", self.config.scope.capability_line())
            base = base.replace("{max_actions}", str(MAX_HTTP_ACTIONS))
        parts = [part for part in (self._doctrine(), base, self._activated_section()) if part]
        return "\n\n".join(parts)

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

            budget = self.config.request_budget
            if budget is not None and budget.exhausted:
                # 停下来,而不是让 reasoner 去规划一批发不出去的请求。它规划一次就要
                # 一次 LLM 调用,而结果注定是 request_budget_exhausted。
                stop_reason = "request_budget_exhausted"
                break

            # Reason phase
            reason_result = self._reason(snapshot)
            if reason_result is None:
                stop_reason = "reasoner_failed"
                errors.append(self._last_reason_error or "reasoner_returned_none")
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
            #
            # 这一轮的墙钟几乎全花在 Explorer 那次 LLM 调用上,所以选中的 intent
            # 一起跑而不是排队跑。安全性由黑板自己保证:claim_intent 是文件锁里的
            # 读-改-写,两个线程(或两个进程)抢同一个 intent 只会有一个拿到。
            # 出网仍然只有一个桶 —— 并发的是"思考",不是"请求速率"。
            planned = list(self._plan_exploration(selected, snapshot))
            results = self._explore_batch(planned, snapshot)
            for (intent_id, _hypothesis, _check), result in zip(planned, results):
                if result.status == "deferred":
                    # 依赖未就绪或已被别的 worker 领走 —— 不是错误,下轮再看。
                    self._timeline("deferred", intent_id, result.dead_end_reason[:120] or "not_claimable")
                    continue
                total_explored += 1
                # 只要这条结果带了 finding 就计数,而不是只在 fact_added 时计数。
                # 高置信 finding 走的是 needs_human(标 blocked、等人工复核),它既不是
                # fact_added 也不是 dead_end —— 旧写法直接漏掉它,于是**最好的那几条
                # 发现反而不进 total_findings**,运行摘要报 0,操作员以为什么都没挖到。
                # 2026-09-21 实测:黑板上有 3 条 high 置信 hint(版本泄露 / 未授权配置
                # 读取 / uiconfig 泄露内部角色),摘要却是 total_findings: 0。
                total_findings += len(result.findings)
                if result.status == "dead_end":
                    total_dead_ends += 1
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
            # 这一轮发了多少请求、上限是多少。红线要求"最小化",所以这个数要看得见 ——
            # 只靠速率桶的话,"多快"有据可查,"多少"是空的。
            "requests_used": int(self.config.request_budget.used) if self.config.request_budget else 0,
            "request_budget": int(self.config.request_budget.limit) if self.config.request_budget else 0,
            # 这次运行激活了哪几本打法、谁触发的 —— 复盘时才说得清"为什么它这轮打得不一样"。
            "activated_knowledge": list(self._activation_log),
        }

    def _timeline(self, kind: str, intent_id: str, summary: str) -> None:
        """Append one observation to the blackboard timeline; never fatal."""
        try:
            self.blackboard.timeline_append(kind, intent_id=intent_id, summary=summary)
        except Exception:  # noqa: BLE001 - timeline is advisory
            pass

    def _record_http_action(self, url: str, body: str, content_type: str,
                            result: Mapping[str, Any], reason: str, *,
                            kind: str = "action") -> None:
        """Audit one request, and keep the blackboard's copy a fingerprint.

        Split in two on purpose. The full request and response go to
        ``http-actions.jsonl`` in the run directory — that is the record a reviewer
        reads, and it is the only place a request body is written down. The
        blackboard timeline gets a *fingerprint* only: the blackboard's whole
        redaction is one regex (``core.src_blackboard._SECRET_TEXT``), and a request
        body is exactly the sort of thing that walks past a regex.
        """
        method = str(result.get("method") or "GET")
        if method not in {"GET", "HEAD"}:
            self._timeline(
                "http_action", "",
                f"{method} {url} → {result.get('status')} body={_fingerprint(body, content_type)} "
                f"reason={reason[:80]}",
            )
        record_http_action(self.config.blackboard_path, url=url, body=body,
                           content_type=content_type, result=result, reason=reason,
                           kind=kind)

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
            self._system(REASONER_SYSTEM), user_msg,
            timeout=self.config.timeout,
            prefer=self.config.reasoner_prefer,
            only=self.config.reasoner_only,
        )
        if raw is None:
            self._last_reason_error = f"llm_failed: {last_llm_error() or 'no content'}"
            return None
        parsed = _parse_json_response(raw)
        if parsed is None:
            self._last_reason_error = (f"unparseable({len(raw)} chars, tail={raw[-60:]!r})")
            return None
        self._last_reason_error = ""
        self._activate_from_reasoner(parsed)
        return parsed

    def _activate_from_reasoner(self, parsed: Dict[str, Any]) -> None:
        """Activate after the reasoner has spoken — the cards land from the next cycle."""
        declared = parsed.get("read_knowledge")
        if isinstance(declared, list):
            self.activate([str(name) for name in declared], source="reasoner")
        hypotheses = " ".join(
            str(item.get("hypothesis") or "")
            for item in (parsed.get("selected_intents") or [])
            if isinstance(item, dict)
        )
        self.activate_from_signals(
            str(parsed.get("reasoning") or ""), hypotheses, source="reasoner-signal")

    def _activate_from_explorer(self, parsed: Optional[Dict[str, Any]], *extra: str) -> None:
        """Activate on what the response actually showed, for the cycles that follow."""
        if not isinstance(parsed, dict):
            return
        declared = parsed.get("read_knowledge")
        if isinstance(declared, list):
            self.activate([str(name) for name in declared], source="explorer")
        self.activate_from_signals(
            str(parsed.get("analysis") or ""),
            str(parsed.get("suggested_next") or ""),
            json.dumps(parsed.get("findings") or [], ensure_ascii=False),
            *extra,
            source="explorer-signal",
        )

    def _explore_batch(
        self,
        planned: Sequence[Tuple[str, str, str]],
        snapshot: Dict[str, Any],
    ) -> List[ExploreResult]:
        """Run this cycle's selected intents, concurrently when asked to.

        Results come back in ``planned`` order, not completion order: the counters,
        the timeline and the error list have to be the same whichever thread
        happened to finish first, or a run stops being reproducible.

        One intent crashing must not take the batch with it — it becomes an
        ``error`` result and shows up in the run summary's ``errors`` like any
        other failure.
        """
        if not planned:
            return []
        width = min(int(self.config.max_parallel_explore), len(planned), MAX_PARALLEL_EXPLORE)
        if width <= 1:
            return [self._explore(i, h, c, snapshot) for i, h, c in planned]
        with ThreadPoolExecutor(max_workers=width, thread_name_prefix="src-explore") as pool:
            futures = [pool.submit(self._explore, i, h, c, snapshot) for i, h, c in planned]
            results: List[ExploreResult] = []
            for (intent_id, _hypothesis, _check), future in zip(planned, futures):
                try:
                    results.append(future.result())
                except Exception as exc:  # noqa: BLE001 - one intent must not sink the batch
                    results.append(ExploreResult(intent_id, "error",
                                                 dead_end_reason=f"explore_crashed:{exc}"))
            return results

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
        # probe_url 才真的去取:``target`` 是去敏后的展示形式(每个参数值都是
        # [redacted]),请求它必然是 404 —— 而候选队列只存展示形式。
        target_url = str(intent.get("probe_url") or intent.get("target") or target_url).strip()

        # Fetch
        fetch_result = _fetch_for_analysis(
            target_url, self.config.scope,
            fetcher=self.config.fetcher,
            budget=self.config.request_budget,
        )
        # 这个请求以前只进时间线、不进 http-actions.jsonl,于是"到底发过什么"缺了第一跳。
        # 被拒的同样记 —— 记录里要能看出"它想过但没发出去"。
        self._record_http_action(target_url, "", "", fetch_result, "intent fetch",
                                 kind="intent_fetch")

        if fetch_result["error"]:
            error = fetch_result["error"]
            if _is_terminal_refusal(error):
                # 治理拒绝重试多少次都是同一个结果 —— URL 不在范围里、方法没声明、
                # 请求形状过不了闸门、额度用完。以前它和网络抖动走同一条路,一个注定
                # 失败的候选被重新规划到 3 次,白烧 LLM 调用和圈数。
                self.blackboard.fail(
                    claimed_intent_id, self._worker_id, f"refused:{error[:120]}",
                    max_attempts=1,
                )
                self._timeline("refused", claimed_intent_id, error[:120])
                return ExploreResult(claimed_intent_id, "dead_end",
                                     dead_end_reason=f"refused:{error}")
            # Transient network failure → requeue with retry, don't burn the intent.
            self._timeline("retry", claimed_intent_id, f"fetch_error: {error[:120]}")
            self.blackboard.fail(
                claimed_intent_id, self._worker_id,
                f"fetch_error:{error[:120]}",
                backoff_seconds=RETRY_BACKOFF_SECONDS,
            )
            return ExploreResult(
                claimed_intent_id, "error",
                dead_end_reason=error,
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
                summary=(f"{fetch_result.get('method') or 'GET'} {target_url} → "
                         f"{fetch_result['status']} ({len(fetch_result['body'])}B)"),
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
            shape_section=_shape_signals_section(intent.get("hypotheses"), target_url),
            status=fetch_result["status"],
            headers_text=_sanitize_headers(fetch_result["headers"]),
            body_limit=BODY_LIMIT,
            body_text=body_text if body_text else "(empty response body)",
        )

        raw = self._complete(
            self._system(EXPLORER_SYSTEM), user_msg,
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
                action_body = str(action.get("body", "") or "")
                content_type = str(action.get("content_type", "") or "")
                reason = str(action.get("reason", ""))[:200]
                if not action_url:
                    continue
                # 准入只有一处 —— _fetch_for_analysis 里的那五道闸门。这里再写一份
                # "允许哪些动词"就是第二份治理,而第二份迟早和第一份不一样。
                fr = _fetch_for_analysis(
                    action_url, self.config.scope,
                    method=method, body=action_body, content_type=content_type,
                    fetcher=self.config.fetcher, requester=self.config.requester,
                    budget=self.config.request_budget,
                )
                # 被拦下来的尝试同样要审计:否则"模型试过什么"没有任何记录。
                self._record_http_action(action_url, action_body, content_type, fr, reason)
                if fr["error"]:
                    action_results.append(f"BLOCKED {fr['method']} {action_url}: {fr['error'][:120]}")
                else:
                    action_results.append(
                        f"--- {fr['method']} {action_url} (reason: {reason}) ---\n"
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
                self._system(EXPLORER_SYSTEM), followup_msg,
                timeout=self.config.timeout,
                prefer=self.config.explorer_prefer,
                only=self.config.explorer_only,
            )
            if raw is None:
                break
            parsed = _parse_json_response(raw)

        # 这一轮看到的东西决定后面几轮带哪本打法上路 —— 激活的是**下一轮**的 prompt。
        self._activate_from_explorer(parsed, body_text, hypothesis or "")
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
    max_parallel_explore: int = 3,
    reasoner_prefer: str = "deepseek",
    explorer_prefer: str = "",
    worker_id: str = "",
    fetcher: Optional[Callable] = None,
    requester: Optional[Callable] = None,
    llm_complete_fn: Optional[Callable] = None,
    timeout: float = 60.0,
    enable_recall: bool = True,
    recall_limit: int = 5,
    enable_timeline_compress: bool = True,
    timeline_keep: int = 40,
    timeline_max_chars: int = 1600,
    enable_dependencies: bool = True,
    skill_pack: str = "pentest",
    knowledge_seed: Sequence[str] = (),
    request_budget: Optional[RequestBudget] = None,
) -> Dict[str, Any]:
    """Run the SRC agent loop and return a summary.

    ``request_budget`` defaults to a fresh :class:`RequestBudget` — every run is capped
    unless a caller deliberately hands in its own (the Console hands in the one that
    belongs to the job, so fan-out and the run share a single count).
    """
    config = AgentConfig(
        blackboard_path=Path(blackboard_path),
        scope=scope,
        reasoner_prefer=reasoner_prefer,
        explorer_prefer=explorer_prefer,
        max_cycles=max_cycles,
        max_explore_per_cycle=max_explore_per_cycle,
        max_parallel_explore=max_parallel_explore,
        worker_id=worker_id,
        fetcher=fetcher,
        requester=requester,
        llm_complete_fn=llm_complete_fn,
        timeout=timeout,
        enable_recall=enable_recall,
        recall_limit=recall_limit,
        enable_timeline_compress=enable_timeline_compress,
        timeline_keep=timeline_keep,
        timeline_max_chars=timeline_max_chars,
        enable_dependencies=enable_dependencies,
        skill_pack=skill_pack,
        knowledge_seed=tuple(knowledge_seed),
        request_budget=request_budget or RequestBudget(),
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
