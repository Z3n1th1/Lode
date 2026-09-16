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
from typing import Any, Callable, Dict, List, Optional

from core.modes import Mode
from core.targets import TargetSplit, assets, first_url, scope_lists, split_targets

REPLY = "reply"
ESCALATE = "escalate"

# 匹配是"包含"而不是"等于",所以这里放的是**词根**:`扫` 一次就盖住 扫 / 扫一下 /
# 扫描 / 帮我扫扫,不用把每种说法都列一遍(以前列了 扫一下/扫下/扫描 三个,然后
# 操作员打一个"扫"字就什么也不认)。歧义词根(看/查)故意不放:那些交给兜底分类器,
# 它读得懂"看看 https://x.com 的首页设计"不是要扫,而包含匹配读不懂。
_ACTION_WORDS = (
    "扫", "测", "挖", "审计", "漏洞", "利用", "打点", "信息收集", "侦察",
    "scan", "hunt", "audit", "fuzz", "exploit", "recon", "pentest",
)
# 目标数量到这个数以上,才要求它必须是这句话的主体。
# 一句话里带一两个目标是正常用法("对 x.com 做信息收集"),不用判。
_LIST_CHECK_MIN = 5
_LIST_DOMINANCE = 0.5
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
    # 一次升级可以带多个目标(每个目标一个任务)。``target`` 保留为第一个,
    # 飞书那条路和既有调用方只认它。
    targets: List[str] = field(default_factory=list)

    @property
    def escalates(self) -> bool:
        return self.action == ESCALATE


def _accepted_count(split: TargetSplit) -> int:
    return len(split.entrypoints) + len(split.domains) + len(split.hosts)


def _targets_are_the_subject(split: TargetSplit) -> bool:
    """目标够多时,要求它必须是这句话的主体。

    粘一整页程序说明进来时,里面散落的文档链接、GitHub 链接、监管机构链接都会被
    识别成目标。按数量开跑等于对一堆越权域名发请求 —— 所以清单要占这句话的一半以上
    才自动开跑,否则只在对话里回报识别到了什么。
    """
    count = _accepted_count(split)
    if count < _LIST_CHECK_MIN:
        return True
    return count >= max(1, split.tokens) * _LIST_DOMINANCE


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

    # 2. 目标 + 动作词,且在会升级的模式里 -> 起子任务(每个目标一个)
    split = split_targets(text)
    seeds = [asset.display for asset in assets(split)]
    if seeds and _has_action_word(text):
        if not mode.may_escalate:
            return RouteDecision(action=REPLY, mode=mode.name, reason="autonomy_none")
        if not _targets_are_the_subject(split):
            return RouteDecision(action=REPLY, mode=mode.name, reason="targets_not_a_list")
        return RouteDecision(action=ESCALATE, subtask_kind=SUBTASK_FOR_MODE.get(mode.name, "src_loop"),
                             target=seeds[0], targets=seeds, mode=mode.name,
                             reason="targets+action", scope=scope_lists(split))

    # 3. 不确定的(目标没配动作词 / 动作词没配目标 / 只有个 URL) -> 便宜的兜底分类。
    #    ``seeds`` 也算不确定:操作员打了"扫"以外的说法时,别的地方(包含匹配)读不懂,
    #    但分类器读得懂。没有这一步,一句没人认识的话就永远是"只回话"。
    url = first_url(text)
    ambiguous = bool(_has_action_word(text)) or bool(seeds) or bool(url)
    if ambiguous and allow_llm and llm_complete is not None and mode.may_escalate:
        if seeds and not _targets_are_the_subject(split):
            return RouteDecision(action=REPLY, mode=mode.name, reason="targets_not_a_list")
        doc = _llm_classify(text, mode, llm_complete)
        if doc and str(doc.get("action")) == ESCALATE:
            # 分类器只回答"要不要开跑";目标以解析结果为准 —— 规则那条路的目标
            # 已经过了闸门并归一化过,模型嘴里那个没有。解析出几个就开几个,和
            # 规则那条路同一个形状。
            names = list(seeds) or [s for s in [str(doc.get("target") or url or "")] if s]
            if names:
                return RouteDecision(action=ESCALATE,
                                     subtask_kind=str(doc.get("subtask_kind") or SUBTASK_FOR_MODE.get(mode.name, "src_loop")),
                                     target=names[0], targets=names, mode=mode.name,
                                     reason=str(doc.get("reason") or "llm"),
                                     scope=scope_lists(split) if seeds else {})
    return RouteDecision(action=REPLY, mode=mode.name, reason="default_reply")


__all__ = ["RouteDecision", "route", "REPLY", "ESCALATE", "SUBTASK_FOR_MODE"]
