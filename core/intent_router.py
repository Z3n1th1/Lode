"""Deterministic-first intent router for the unified conversation.

Decides, for one user turn, whether to just reply or to escalate into a subtask
(one black-box hunt against an authorized target). Rules run first — they are cheap,
testable and never block — and only genuinely ambiguous text falls through to a
single cheap LLM classification (which fails safe to ``reply``).

Escalation maps onto the existing blackboard: the subtask becomes an intent
(``depends_on`` = DAG edges) claimed with a lease by the job runner.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

from core.modes import Mode

REPLY = "reply"
ESCALATE = "escalate"

_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_ACTION_WORDS = (
    "扫描", "扫一下", "扫下", "测一下", "测试", "探测", "挖洞", "挖一下", "挖",
    "审计", "看漏洞", "找漏洞", "漏洞", "利用", "打点", "信息收集", "侦察",
    "scan", "hunt", "audit", "fuzz", "exploit", "recon", "pentest",
)
# "进入挖洞模式" / "切换到渗透模式"
_MODE_CMD_RE = re.compile(
    r"(?:进入|切换到|切到|使用|用|开启)\s*([A-Za-z_\u4e00-\u9fa5]{1,12}?)\s*模式"
)

# Chinese/alias -> canonical mode name
_MODE_ALIASES: Dict[str, str] = {
    "挖洞": "pentest", "黑盒": "pentest", "黑盒挖洞": "pentest", "打点": "pentest",
    "渗透": "pentest", "渗透测试": "pentest", "pentest": "pentest",
    "src": "pentest", "SRC": "pentest", "src黑盒": "pentest", "sr_c黑盒": "pentest",
    "src_blackbox": "pentest",
    "闲聊": "chat", "聊天": "chat", "对话": "chat", "chat": "chat",
}

SUBTASK_FOR_MODE: Dict[str, str] = {
    "pentest": "src_loop",
}


@dataclass
class RouteDecision:
    action: str = REPLY
    subtask_kind: str = ""
    target: str = ""
    mode: str = ""
    reason: str = ""
    scope: Dict[str, Any] = field(default_factory=dict)

    @property
    def escalates(self) -> bool:
        return self.action == ESCALATE


def _first_url(text: str) -> str:
    match = _URL_RE.search(text or "")
    return match.group(0).rstrip(".,;)]}，。；）】") if match else ""


def _mode_command(text: str) -> str:
    match = _MODE_CMD_RE.search(text or "")
    if not match:
        return ""
    token = match.group(1).strip()
    return _MODE_ALIASES.get(token) or _MODE_ALIASES.get(token.lower()) or ""


def _has_action_word(text: str) -> bool:
    lowered = (text or "").lower()
    return any(word.lower() in lowered for word in _ACTION_WORDS)


def _llm_classify(text: str, mode: Mode, llm_complete: Callable[..., Optional[str]]) -> Optional[Dict[str, Any]]:
    schema = ('Return strict JSON: {"action":"reply"|"escalate","subtask_kind":"",'
              '"target":"","reason":""}. Escalate only if the user is asking to actively '
              'test/scan/attack a system.')
    raw = llm_complete("You route user intent for a security agent.\n" + schema, text, timeout=15)
    if not raw:
        return None
    try:
        doc = json.loads(raw[raw.find("{"): raw.rfind("}") + 1])
    except (ValueError, AttributeError):
        return None
    return doc if isinstance(doc, dict) else None


def route(user_text: str, *, mode: Mode, llm_complete: Optional[Callable[..., Optional[str]]] = None,
          allow_llm: bool = True) -> RouteDecision:
    """Classify one turn. Never raises; unknown input replies."""
    text = (user_text or "").strip()
    if not text:
        return RouteDecision(action=REPLY, mode=mode.name, reason="empty")

    # 1. explicit mode switch ("进入挖洞模式") — reply + mode_changed
    requested = _mode_command(text)
    if requested:
        return RouteDecision(action=REPLY, mode=requested, reason="mode_command")

    # 2. URL + action verb in an escalating mode -> launch a subtask
    url = _first_url(text)
    if url and _has_action_word(text):
        if mode.may_escalate:
            return RouteDecision(action=ESCALATE, subtask_kind=SUBTASK_FOR_MODE.get(mode.name, "src_loop"),
                                 target=url, mode=mode.name, reason="url+action")
        return RouteDecision(action=REPLY, mode=mode.name, reason="autonomy_none")

    # 3. ambiguous (action verb but no URL, or URL with no verb) -> optional LLM
    ambiguous = bool(_has_action_word(text)) or bool(url)
    if ambiguous and allow_llm and llm_complete is not None and mode.may_escalate:
        doc = _llm_classify(text, mode, llm_complete)
        if doc and str(doc.get("action")) == ESCALATE:
            target = str(doc.get("target") or url or "")
            if target:
                return RouteDecision(action=ESCALATE,
                                     subtask_kind=str(doc.get("subtask_kind") or SUBTASK_FOR_MODE.get(mode.name, "src_loop")),
                                     target=target, mode=mode.name,
                                     reason=str(doc.get("reason") or "llm"))
    return RouteDecision(action=REPLY, mode=mode.name, reason="default_reply")


__all__ = ["RouteDecision", "route", "REPLY", "ESCALATE", "SUBTASK_FOR_MODE"]
