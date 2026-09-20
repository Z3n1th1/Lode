"""Judge whether a blob of text is an authorisation document, and read it.

Three Console entry points feed a run from a whole scope document — a paste into
the conversation, a file uploaded through the UI, and a file dropped into the
watched inbox.  They all call this module, because three copies of "what counts
as a document" would disagree, and the one that disagreed would be the one that
authorised something.

This is deliberately **not** in ``core/``: it needs :class:`SurfaceScope`, and no
module under ``core/`` imports ``agents/`` — the dependency runs one way.  So the
parser lives next to the governance primitive it produces.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Tuple
from urllib.parse import urlsplit

from agents.surface_discovery import SurfaceScope
from core.targets import MAX_ENTRIES, public_target_reason

# 文档没写 max_fanout 时起几个 job。速率是硬盖(见 core/rate_limit),所以这个数
# 管的是"队列有多长",不是"程序会被打多快"。
DEFAULT_MAX_FANOUT = 30
# 依据是 targets.py 那份"一次能识别的资产数":超过它,文档里就有一部分主机
# 根本没经过那道闸门。上限不是拍脑袋来的。
HARD_MAX_FANOUT = MAX_ENTRIES

# 一份能通过 require_authorization 的文档,至少要有一个主机类键和一个 authorization。
# 这两个键一起出现,是"这是授权文档"和"这是聊到一半的 JSON"之间最强的分界。
_HOST_KEYS = ("allowed_hosts", "hosts", "seed_urls", "allowed_domains", "forbidden_hosts", "forbidden")
_AUTHORIZATION_KEYS = ("authorization",)


class ScopeDocumentError(ValueError):
    """这份文本看着像授权文档,但读不成一份可以开跑的授权。

    ``reason`` 是给调用方和前端翻译用的短标签;``detail`` 用来点名具体是哪些域、
    哪几个主机 —— 只说"不行"而不说"哪个不行",操作员只能靠猜。
    """

    def __init__(self, reason: str, *, detail: str = "") -> None:
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class ScopeDocument:
    """一份读通了的授权文档,以及从它派生的可执行形状。"""

    document: Mapping[str, Any]
    scope: SurfaceScope
    # 精确主机名,保持文档里的顺序 —— 操作员的排列往往就是他心里的优先级。
    hosts: Tuple[str, ...]
    # 被 targets.py 那道闸门拦掉的主机:(host, reason)。不静默丢。
    rejected: Tuple[Tuple[str, str], ...]
    max_fanout: int


def _nested(document: Mapping[str, Any]) -> Mapping[str, Any]:
    """Mirror ``SurfaceScope.from_mapping``'s nesting rule so both read the same keys."""
    inner = document.get("scope")
    return inner if isinstance(inner, Mapping) else document


def _unwrap_fence(text: str) -> Optional[str]:
    """Return the payload of a whole-text code fence, the bare text, or ``None``.

    "整段" is the point: a document is the whole message, not a paragraph that
    happens to contain braces.  Prose with JSON embedded in it is a sentence about
    a document, and treating it as one would let a quoted example authorise a run.
    """
    stripped = (text or "").strip()
    if not stripped.startswith("```"):
        return stripped
    lines = stripped.splitlines()
    if len(lines) < 2 or lines[-1].strip() != "```":
        return None  # 没闭合的围栏不是一份完整文档
    return "\n".join(lines[1:-1]).strip()


def looks_like_scope_document(text: str) -> Optional[Mapping[str, Any]]:
    """The (quote-free) document, or ``None`` if this is not one.

    Conservative on purpose.  Anything that fails here falls through to the normal
    chat path, so a false negative costs the operator one sentence of explanation,
    while a false positive would turn an example into an authorisation.
    """
    payload = _unwrap_fence(text)
    if not payload:
        return None
    try:
        document = json.loads(payload)
    except (ValueError, TypeError):
        return None
    if not isinstance(document, dict):
        return None
    # 别的 schema 有自己的入口,不能从这条门进来。
    if document.get("schema") == "TargetCard/v1":
        return None
    # intake 载荷里有 target_url —— 那是一个目标,不是一份授权。
    if document.get("target_url"):
        return None
    data = _nested(document)
    if not any(key in document or key in data for key in _AUTHORIZATION_KEYS):
        return None
    if not any(key in document or key in data for key in _HOST_KEYS):
        return None
    return document


def _hosts_from_seed_urls(document: Mapping[str, Any]) -> Tuple[str, ...]:
    """Hostnames named by ``seed_urls``.

    Only the host, never the registrable domain: a seed URL names one host, and
    widening it to its domain is exactly the ``9045ee3`` incident.
    """
    data = _nested(document)
    raw = data.get("seed_urls") or document.get("seed_urls") or []
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, (list, tuple)):
        return ()
    hosts = []
    for item in raw:
        value = str(item).strip()
        if not value:
            continue
        parsed = urlsplit(value if "://" in value else f"https://{value}")
        host = (parsed.hostname or "").strip().rstrip(".").lower()
        if host:
            hosts.append(host)
    return tuple(hosts)


def _ordered_declared_hosts(document: Mapping[str, Any], scope: SurfaceScope) -> Tuple[str, ...]:
    """Every exact host the document names, in document order, de-duplicated.

    ``allowed_ips`` 里的**精确**地址也算主机:``check_url`` 对 IP 目标只查
    ``allowed_ips``,所以把它们漏掉等于"文档里写了但永远跑不了"。带 ``/`` 的网段不算
    —— 那是一片地址,和域模式是同一件事(见 :func:`parse_scope_document`)。
    """
    candidates = list(scope.allowed_hosts) + list(_hosts_from_seed_urls(document)) + list(scope.allowed_ips)
    seen: set[str] = set()
    ordered: list[str] = []
    for item in candidates:
        host = str(item).strip().rstrip(".").lower()
        if not host or host in seen:
            continue
        seen.add(host)
        ordered.append(host)
    return tuple(ordered)


def max_fanout_for(document: Mapping[str, Any]) -> int:
    """The single reader for this cap.  A second one would be a second policy."""
    data = _nested(document)
    raw = data.get("max_fanout", document.get("max_fanout"))
    if raw is None or raw == "":
        return DEFAULT_MAX_FANOUT
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        # 读不懂就退回默认,不猜一个更大的数 —— 这个数是往上走的风险。
        return DEFAULT_MAX_FANOUT
    return max(1, min(value, HARD_MAX_FANOUT))


def parse_scope_document(document: Mapping[str, Any]) -> ScopeDocument:
    """Turn a document into the scope it authorises, or say precisely why not."""
    if not isinstance(document, Mapping):
        raise ScopeDocumentError("scope_document_not_an_object")

    scope = SurfaceScope.from_mapping(document)
    try:
        scope.require_authorization()
    except ValueError as exc:
        # 复用 canonical 的原因码(surface_authorization_required /
        # surface_scope_required),不另造一套词汇。
        raise ScopeDocumentError(str(exc)) from exc

    if scope.allowed_domains:
        # 域模式授权的是"这一整片子域",而不是操作员逐一看过的那几台主机。
        # 这份文档不能从 Console 这条路进来。
        raise ScopeDocumentError(
            "scope_document_domains_not_allowed",
            detail="、".join(scope.allowed_domains),
        )

    ranges = [item for item in scope.allowed_ips if "/" in str(item)]
    if ranges:
        # CIDR 是"这一整片地址",和域模式同一件事、同一个理由:授权了操作员没有
        # 逐一看过的目标。精确地址照收(check_url 对 IP 只查 allowed_ips)。
        raise ScopeDocumentError(
            "scope_document_ip_range_not_allowed",
            detail="、".join(str(item) for item in ranges),
        )

    hosts: list[str] = []
    rejected: list[Tuple[str, str]] = []
    for host in _ordered_declared_hosts(document, scope):
        if host.startswith("*."):
            # 通配主机和域模式是同一件事的两种写法,同一个理由拒绝。
            rejected.append((host, "scope_document_wildcard_not_allowed"))
            continue
        reason = public_target_reason(host)
        if reason:
            rejected.append((host, reason))
            continue
        hosts.append(host)

    if not hosts:
        raise ScopeDocumentError("scope_document_no_hosts")

    return ScopeDocument(
        document=document,
        scope=scope,
        hosts=tuple(hosts),
        rejected=tuple(rejected),
        max_fanout=max_fanout_for(document),
    )


__all__ = [
    "DEFAULT_MAX_FANOUT", "HARD_MAX_FANOUT", "ScopeDocument", "ScopeDocumentError",
    "looks_like_scope_document", "max_fanout_for", "parse_scope_document",
]
