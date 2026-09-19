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

from core.modes import Mode, get_mode
from core.targets import TargetSplit, assets, first_url, scope_lists, split_targets

REPLY = "reply"
ESCALATE = "escalate"

# 决策上的机器码,由调用方翻译成人话(渲染文案不属于这里)。
# 对话模式下认出了"目标 + 动作词"却因为自治级别是 none 开不了跑 —— 这时候
# 静默只回话等于把操作员晾在那儿,得明说切到挖洞就能跑。
HINT_MODE_BLOCKS_HUNT = "mode_blocks_hunt"

# 匹配是"包含"而不是"等于",所以这里放的是**词根**:`扫` 一次就盖住 扫 / 扫一下 /
# 扫描 / 帮我扫扫,不用把每种说法都列一遍(以前列了 扫一下/扫下/扫描 三个,然后
# 操作员打一个"扫"字就什么也不认)。歧义词根(看/查)故意不放:那些交给兜底分类器,
# 它读得懂"看看 https://x.com 的首页设计"不是要扫,而包含匹配读不懂。
_ACTION_WORDS = (
    "扫", "测", "挖", "审计", "漏洞", "利用", "打点", "信息收集", "侦察", "建面",
    "scan", "hunt", "audit", "fuzz", "exploit", "recon", "pentest",
)
# 要"面"不要"循环":操作员说得出这句话,是因为建面便宜、深度推理贵,而他只想先看看
# 这个站有什么。以前没有这句话,不管你说什么都会起 src_loop —— 于是 surface_scan
# 这个 handler 虽然有、UI 也渲染它,却永远没人建得出来(全仓 grep 不到生产者)。
_SURFACE_ONLY_WORDS = (
    "只建面", "先建面", "只做面", "只摸面", "只侦察", "先侦察", "只收集信息",
    "surface only",
)
SURFACE_SCAN_KIND = "surface_scan"
# 目标数量到这个数以上,才要求它必须是这句话的主体。
# 一句话里带一两个目标是正常用法("对 x.com 做信息收集"),不用判。
_LIST_CHECK_MIN = 5
_LIST_DOMINANCE = 0.5
# 换模式的动词。"改成 / 切成 / 换成 / 转到 / 直接到"是有意加进来的:操作员说的是
# "改成挖洞""直接到挖洞",而以前只认"进入…模式"一种骨架,这些说法全部识别不到 ——
# 落到兜底分类器,再被对话模式的 autonomy=none 挡回"只回话",看起来就像产品不让人切模式。
_MODE_VERBS = "进入|直接到|切换到|切到|改成|切成|换成|转到|使用|用|开启"
# 带"模式"的写法优先:它把模式名夹死在两个界标中间,所以认不出的名字
# ("进入 CTF 模式")必须在这里就落空,不能掉到下面那条更宽的正则上再捞一遍。
_MODE_CMD_RE = re.compile(
    rf"(?:{_MODE_VERBS})\s*([A-Za-z_\u4e00-\u9fa5]{{1,12}}?)\s*模式"
)
# 不带"模式"的写法("改成挖洞")。中文和字母连写没有词边界,所以先取动词后面那一串
# 候选,再从长到短去比别名表 —— "改成挖洞然后扫这个站"靠这个找到"挖洞",而
# "用聊天室"不会误命中"聊天"。别名表才是真正的闸门:候选认不出来就不算模式指令。
_MODE_BARE_RE = re.compile(
    rf"(?:{_MODE_VERBS})\s*([A-Za-z_\u4e00-\u9fa5]{{1,12}})"
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
    # 一个机器码(见 HINT_* 常量),由 console/jobs.py 翻译成给操作员看的一句话。
    # 只用在"本该开跑、被模式挡住"这种情况上,正常路径留空。
    hint: str = ""

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


def _alias(token: str) -> str:
    """Canonical mode name for one candidate, or ``""`` when it is not a mode."""
    token = (token or "").strip()
    return _MODE_ALIASES.get(token) or _MODE_ALIASES.get(token.lower()) or ""


# 字母/数字/下划线连写时没有词边界,汉字有。这个差别决定了两条路怎么判:
# 前缀扫描是汉字需要的("改成挖洞然后扫…" 得从"挖洞然后扫…"里取出"挖洞"),
# 而 ASCII 别名必须卡边界,否则 "用 srcset 图片" 会把 src 当成模式名。
_ASCII_WORD = re.compile(r"[A-Za-z0-9_]")


def _mode_command(text: str) -> str:
    text = text or ""
    match = _MODE_CMD_RE.search(text)
    if match:
        # 认不出的模式名到此为止:CTF / code-audit 已经不在产品里,它们的指令不该
        # "落到"别的模式上,也不该被下面那条不带"模式"的正则再捞一遍。
        return _alias(match.group(1))
    match = _MODE_BARE_RE.search(text)
    if not match:
        return ""
    run = match.group(1)
    rest = text[match.end(1):]
    for size in range(len(run), 0, -1):
        candidate = run[:size]
        resolved = _alias(candidate)
        if not resolved:
            continue
        following = run[size] if size < len(run) else (rest[:1] or "")
        if _ASCII_WORD.match(candidate[-1]) and following and _ASCII_WORD.match(following):
            continue
        return resolved
    return ""


def _has_action_word(text: str) -> bool:
    lowered = (text or "").lower()
    return any(word.lower() in lowered for word in _ACTION_WORDS)


def _has_surface_only_word(text: str) -> bool:
    lowered = (text or "").lower()
    return any(word.lower() in lowered for word in _SURFACE_ONLY_WORDS)


def _subtask_kind_for(text: str, mode: Mode) -> str:
    """建面,还是整个循环。只有模式自己声明过的两种 kind 会出现在这里。"""
    if _has_surface_only_word(text):
        return SURFACE_SCAN_KIND
    return SUBTASK_FOR_MODE.get(mode.name, "src_loop")


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

    # 1. 显式换模式("进入挖洞模式" / "改成挖洞")。换模式和开跑可以是同一句话 ——
    #    所以这里只把模式定下来,不提前 return:后面几步用**换过之后**的模式判自治
    #    级别。否则 "改成挖洞,扫 a.example.com" 会被旧模式(对话)的 autonomy=none
    #    挡回去,操作员得先发一句换模式、再发一句清单,白跑一个来回。
    requested = _mode_command(text)
    active = get_mode(requested) if requested else mode

    # 2. 目标 + 动作词,且在会升级的模式里 -> 起子任务(每个目标一个)
    split = split_targets(text)
    seeds = [asset.display for asset in assets(split)]
    if seeds and _has_action_word(text):
        if not active.may_escalate:
            return RouteDecision(action=REPLY, mode=requested or mode.name, reason="autonomy_none",
                                 hint=HINT_MODE_BLOCKS_HUNT)
        if not _targets_are_the_subject(split):
            return RouteDecision(action=REPLY, mode=requested or mode.name, reason="targets_not_a_list")
        return RouteDecision(action=ESCALATE, subtask_kind=_subtask_kind_for(text, active),
                             target=seeds[0], targets=seeds, mode=active.name,
                             reason="targets+action", scope=scope_lists(split))

    # 2b. 只换了模式、没有要开跑的东西 -> 只回话(jobs.py 据此发 mode_changed)
    if requested:
        return RouteDecision(action=REPLY, mode=requested, reason="mode_command")

    # 3. 不确定的(目标没配动作词 / 动作词没配目标 / 只有个 URL) -> 便宜的兜底分类。
    #    ``seeds`` 也算不确定:操作员打了"扫"以外的说法时,别的地方(包含匹配)读不懂,
    #    但分类器读得懂。没有这一步,一句没人认识的话就永远是"只回话"。
    url = first_url(text)
    ambiguous = bool(_has_action_word(text)) or bool(seeds) or bool(url)
    if ambiguous and allow_llm and llm_complete is not None and active.may_escalate:
        if seeds and not _targets_are_the_subject(split):
            return RouteDecision(action=REPLY, mode=active.name, reason="targets_not_a_list")
        doc = _llm_classify(text, active, llm_complete)
        if doc and str(doc.get("action")) == ESCALATE:
            # 分类器只回答"要不要开跑";目标以解析结果为准 —— 规则那条路的目标
            # 已经过了闸门并归一化过,模型嘴里那个没有。解析出几个就开几个,和
            # 规则那条路同一个形状。
            names = list(seeds) or [s for s in [str(doc.get("target") or url or "")] if s]
            if names:
                return RouteDecision(action=ESCALATE,
                                     subtask_kind=str(doc.get("subtask_kind") or _subtask_kind_for(text, active)),
                                     target=names[0], targets=names, mode=active.name,
                                     reason=str(doc.get("reason") or "llm"),
                                     scope=scope_lists(split) if seeds else {})
    return RouteDecision(action=REPLY, mode=active.name, reason="default_reply")


__all__ = ["RouteDecision", "route", "REPLY", "ESCALATE", "SUBTASK_FOR_MODE",
           "HINT_MODE_BLOCKS_HUNT"]
