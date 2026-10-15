"""Coordinator routing table for Planner / Worker / Review.

Muteki-shaped swarm: a cheap Planner proposes intents; a Worker (the operator's
主力) claims one; Review audits high-risk evidence. This module is the *only*
door a specialist CLI has into a hunt — structured text, no network, no write,
no shell. HTTP, scope, rate and budget stay hard gates in Lode, like Muteki's
flag gate: they are not a competing agent.

Routing is a table, not a free choice by the model:

    kind / worker_class default engine
    blackbox / worker   current hunter (do not delegate)
    source_repo         claude or codex
    lode_self           codex
    high_risk_review    grok or claude, different from the Worker that judged
    retry_empty         the other backend, once
    conflict            Worker summarises evidence; never a majority vote
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, Mapping, Optional

from core import cli_engines

_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*\n?(.*?)\n?\s*```", re.S)

SPECIALIST_ENGINES = ("claude", "codex", "grok")
HUNTER_ENGINES = cli_engines.ENGINES
DELEGATE_KINDS = (
    "blackbox",
    "source_repo",
    "lode_self",
    "high_risk_review",
    "retry_empty",
    "conflict",
)
MAX_CONTEXT_CHARS = 24_000
MAX_TASK_CHARS = 4_000

_DELEGATE_SYSTEM = """\
你是 Lode 请来的专项分析师，只根据给定上下文做结构化判断。

你没有网络、没有写文件、没有 shell。不要要求去发 HTTP、不要编造没在上下文里出现的证据。
高危结论必须能被上下文证伪或支撑；多个模型意见冲突时列证据，不要靠投票确认漏洞。

只输出 JSON，不要 markdown fence：
{
  "analysis": "观察到了什么",
  "conclusion": "supported|unsupported|needs_human|inconclusive",
  "confidence": "high|medium|low",
  "evidence": ["上下文中的原句或字段"],
  "risks": ["rce|unauth_admin|idor|injection|other"],
  "next": "建议 Planner 下一步（Worker 仍通过 Lode 工具执行）"
}
"""


def _text(value: Any, limit: int) -> str:
    return str(value or "").strip()[:limit]


def hunter_engine(explicit: str = "") -> str:
    """The operator-selected primary hunter (主力挖掘)."""
    return cli_engines.configured_engine(explicit, role="hunter")


def route(kind: str, *, original_engine: str = "", hunter: str = "") -> str:
    """Pick the specialist engine for ``kind``. Unknown kinds stay with the hunter."""
    wanted = str(kind or "").strip().lower()
    original = cli_engines.configured_engine(original_engine, role="hunter")
    primary = hunter_engine(hunter)
    if wanted in {"", "blackbox", "conflict"}:
        return primary
    if wanted == "source_repo":
        return _first_available(("claude", "codex"), avoid="")
    if wanted == "lode_self":
        return "codex"
    if wanted == "high_risk_review":
        return _first_available(("grok", "claude"), avoid=original)
    if wanted == "retry_empty":
        return alternate_engine(original or primary)
    return primary


def alternate_engine(original: str) -> str:
    """One other backend after two empty/corrupt outputs."""
    current = cli_engines.configured_engine(original) if original else hunter_engine()
    if current != "provider":
        return "provider"
    for candidate in ("pi", "grok", "claude", "codex"):
        if candidate != current:
            return candidate
    return "provider"


def may_delegate(kind: str, *, confidence: str = "", high_value: bool = False) -> bool:
    """Ordinary black-box next-request work stays on the hunter."""
    del confidence, high_value
    return str(kind or "").strip().lower() in {
        "source_repo", "lode_self", "high_risk_review", "retry_empty",
    }


def _first_available(candidates: tuple[str, ...], *, avoid: str) -> str:
    skip = str(avoid or "").strip().lower()
    for name in candidates:
        if name == skip:
            continue
        return name
    return candidates[0] if candidates else "provider"


def _parse_analysis(text: str) -> Dict[str, Any]:
    raw = str(text or "").strip()
    if not raw:
        return {}
    candidates = [raw]
    fenced = _JSON_FENCE_RE.search(raw)
    if fenced:
        candidates.append(fenced.group(1).strip())
    start = raw.find("{")
    end = raw.rfind("}")
    if 0 <= start < end:
        candidates.append(raw[start:end + 1])
    for blob in candidates:
        try:
            parsed = json.loads(blob)
        except (ValueError, TypeError):
            continue
        if isinstance(parsed, dict):
            return parsed
    return {"analysis": raw[:4000], "conclusion": "inconclusive",
            "confidence": "low", "evidence": [], "risks": [], "next": ""}


def delegate_analysis(
    engine: str,
    task: str,
    context: str,
    *,
    kind: str = "",
    original_engine: str = "",
    hunter: str = "",
    timeout: float = 90.0,
) -> Dict[str, Any]:
    """Run one specialist pass. Always returns a dict; never raises.

    ``engine`` may be empty: the routing table fills it in. Specialists that are
    missing, logged out, or timed out fall back to the hunter's HTTP provider so
    the hunt continues.
    """
    wanted_kind = str(kind or "").strip().lower() or "blackbox"
    if not may_delegate(wanted_kind):
        return {
            "ok": False,
            "skipped": True,
            "reason": "ordinary_blackbox_stays_on_hunter",
            "engine": hunter_engine(hunter),
            "analysis": {},
        }
    selected = str(engine or "").strip().lower()
    if selected not in SPECIALIST_ENGINES:
        selected = route(wanted_kind, original_engine=original_engine, hunter=hunter)
    if selected not in SPECIALIST_ENGINES and selected != "provider":
        selected = "provider"

    user = (
        f"KIND: {wanted_kind}\nTASK: {_text(task, MAX_TASK_CHARS)}\n\n"
        f"CONTEXT:\n{_text(context, MAX_CONTEXT_CHARS)}"
    )
    used = selected
    text: Optional[str] = None
    error = ""
    if selected != "provider":
        text = cli_engines.complete(selected, _DELEGATE_SYSTEM, user, timeout=timeout)
        if not text:
            error = cli_engines.last_error() or "specialist_failed"
            if cli_engines.fallback_to_provider():
                used = "provider"
            else:
                return {"ok": False, "skipped": False, "reason": error,
                        "engine": selected, "analysis": {}}
    if used == "provider" or not text:
        try:
            from core.llm_client import complete_messages, last_error as provider_error
            message = complete_messages(
                [{"role": "system", "content": _DELEGATE_SYSTEM},
                 {"role": "user", "content": user}],
                timeout=timeout, temperature=0.1,
            )
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "skipped": False,
                    "reason": f"{type(exc).__name__}: {str(exc)[:200]}",
                    "engine": used, "analysis": {}}
        if not message:
            try:
                error = provider_error() or error or "provider_failed"
            except Exception:  # noqa: BLE001
                error = error or "provider_failed"
            return {"ok": False, "skipped": False, "reason": error,
                    "engine": used, "analysis": {}}
        text = str(message.get("content") or "")
        used = "provider"

    analysis = _parse_analysis(text)
    return {
        "ok": True,
        "skipped": False,
        "reason": "",
        "engine": used,
        "requested_engine": selected,
        "kind": wanted_kind,
        "analysis": analysis,
    }


def high_risk_finding(finding: Mapping[str, Any]) -> bool:
    """Whether a finding should get an independent specialist review."""
    blob = json.dumps(dict(finding or {}), ensure_ascii=False).lower()
    markers = (
        "rce", "remote code", "deserialization", "fastjson", "unauth",
        "未授权", "conductor", "workflow", "xxl", "command", "ssti",
        "jndi", "ognl", "spel", "反序列化", "命令执行",
    )
    if any(token in blob for token in markers):
        return True
    severity = str(finding.get("severity") or "").strip().lower()
    return severity in {"high", "critical"}


__all__ = [
    "SPECIALIST_ENGINES",
    "HUNTER_ENGINES",
    "DELEGATE_KINDS",
    "hunter_engine",
    "route",
    "alternate_engine",
    "may_delegate",
    "delegate_analysis",
    "high_risk_finding",
]
