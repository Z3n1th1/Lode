"""Red-team-hardened action policy layered on policy_engine.evaluate_action.

Contract (2026-08-07 策略修订):
- The base A0..F0 grade from evaluate_action is authoritative and is NEVER
  weakened here: an F0/forbid stays forbid; a dangerous-signal or shared-state
  concern can only RAISE to need_human.
- The ONLY relaxation is a NARROW carve-out that turns a base `need_human` for a
  create/modify into `allow_limited` — and ONLY when operator-proven:
    * create: endpoint on the operator-owned inert-surface allowlist AND writing
      as an operator-provisioned test principal (never an agent "benign" claim);
    * modify: the target is proven self-created by the MAC-bound hardened ledger
      (all 5 conditions) AND touches no shared state.
- delete always → need_human. url/callback, privilege/credential, and
  payment/sms/state (cleanup-keyword) creates/modifies always → need_human,
  regardless of allowlist or ledger ownership.

Hardening (2026-08-07 audit, finding H1-1 — semantic kind):
- action_kind no longer trusts the HTTP method alone. REST method-override
  fields/headers (`_method`, `X-HTTP-Method-Override`, ...), RPC-style action
  selectors (`action`/`op`/`cmd`/`type`...), and action tokens in the URL path
  or query (delete/update/refund/删除/取消/...) all ESCALATE the kind.
  Escalation only ever raises severity (delete > modify > create > read);
  a POST to `/notes/123/delete` is a delete and can never auto-allow via the
  inert-surface create carve-out.
"""
from __future__ import annotations

import re
import urllib.parse
from typing import Any, Dict, Iterator, List, Mapping, Optional, Tuple

from . import value_scanners
from .hardened_ledger import is_owned_strict
from .inert_surface import InertSurface

_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

_SEVERITY = {"read": 0, "other": 1, "create": 2, "modify": 3, "delete": 4}

# REST frameworks honor these to tunnel writes through POST/GET.
_METHOD_OVERRIDE_KEYS = ("_method", "_method_override", "method_override",
                         "x-http-method-override", "x-http-method",
                         "x-original-method", "_verb")

# RPC-style action selectors (key names) whose VALUES select the operation.
_ACTION_FIELD_KEYS = ("action", "op", "operation", "verb", "cmd", "do", "act",
                      "method_name", "operationtype", "type",
                      "func", "task", "handler", "mode", "event", "method",
                      "function", "actiontype", "oper",
                      "操作", "类型", "caozuo", "leixing")

_DELETE_TOKENS = ("delete", "remove", "destroy", "purge", "erase", "recycle",
                  "clear", "drop", "trash", "wipe", "del", "rm", "unlink",
                  "删除", "移除", "销毁", "清空", "清除", "作废")
_MODIFY_TOKENS = ("update", "edit", "modify", "patch", "reset", "cancel",
                  "close", "disable", "revoke", "freeze", "suspend",
                  "logout", "signout", "unsubscribe", "sendmail", "sendemail",
                  "sendsms", "refund", "checkout", "transfer", "activate",
                  "修改", "更新", "取消", "关闭", "禁用", "重置", "吊销",
                  "冻结", "停用")


def _method_kind(method: str) -> str:
    # 2026-08-07 review I1：值必须 strip——"X-HTTP-Method-Override: DELETE "
    # 带尾随空白时旧实现失配降级为 other → allow_limited 逃逸。
    m = (method or "").strip().upper()
    if m == "DELETE":
        return "delete"
    if m in ("PUT", "PATCH"):
        return "modify"
    if m == "POST":
        return "create"
    if m in ("GET", "HEAD", "OPTIONS"):
        return "read"
    return "other"


def _iter_kv(obj: Any) -> Iterator[Tuple[str, str]]:
    if isinstance(obj, Mapping):
        for k, v in obj.items():
            if isinstance(v, (Mapping, list, tuple)):
                yield from _iter_kv(v)
            elif v is not None and not isinstance(v, bool):
                yield str(k), str(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _iter_kv(v)


def _decode_variants(val: str, rounds: int = 3, lower: bool = True) -> List[str]:
    """Raw + repeatedly percent-decoded forms. Some stacks (framework + reverse
    proxy combos) decode more than once, so a double-encoded 删除/%25... must
    not hide action semantics. Bounded at `rounds` to stay cheap.
    lower=False 保留原始大小写（驼峰切分需要边界信息，调用方自行 lower）。"""
    variants = [val.lower() if lower else val]
    cur = variants[0]
    for _ in range(rounds):
        try:
            nxt = urllib.parse.unquote(cur)
        except Exception:
            break
        if nxt == cur:
            break
        variants.append(nxt)
        cur = nxt
    return variants


_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def _split_camel(token: str) -> List[str]:
    """驼峰边界切分：deleteNote → [delete, note]（2026-08-07 review I2：
    只做 [_-.;] 切分时 camelCase 动作段 deleteNote/trashItem 整词失配逃逸）。"""
    parts = _CAMEL_BOUNDARY_RE.split(token)
    return [p for p in parts if p]


def _path_segments(action: Mapping[str, Any]) -> List[str]:
    """URL path split into tokens, raw + percent-decoded (CJK-aware).

    Segments are split on matrix-parameter `;` as well: `/notes;delete` is
    routed as `notes` by some frameworks but the matrix token can carry action
    semantics, so it is treated as a token (fail-safe direction). CamelCase
    segments are additionally split at case boundaries (fail-safe direction).
    """
    out: List[str] = []
    for field in ("url", "target", "path", "endpoint"):
        val = str(action.get(field) or "")
        if not val:
            continue
        # 保留大小写解码（驼峰边界需要），输出统一 lower
        for variant in _decode_variants(val, lower=False):
            try:
                p = urllib.parse.urlsplit(variant).path
            except Exception:
                p = variant
            for seg in re.split(r"[/\\]", p):
                for t in re.split(r"[_.\-;]+", seg):
                    if not t:
                        continue
                    out.append(t.lower())
                    out.extend(s.lower() for s in _split_camel(t) if s.lower() != t.lower())
    return out


def _path_haystack(action: Mapping[str, Any]) -> str:
    """Joined raw+decoded path text (NOT split into segments). Substring matching
    over this catches camelCase / CJK-concatenated action routes that exact
    segment-membership missed — `/api/deleteUser`, `/userDelete/1`, `/删除账户`.
    Over-match only ever raises to need_human (fail-safe)."""
    hay: List[str] = []
    for field in ("url", "target", "path", "endpoint"):
        val = str(action.get(field) or "")
        if val:
            hay.extend(_decode_variants(val))
    return " ".join(hay)


def _path_kind(action: Mapping[str, Any]) -> Optional[str]:
    hay = _path_haystack(action)
    if any(t in hay for t in _DELETE_TOKENS):
        return "delete"
    if any(t in hay for t in _MODIFY_TOKENS):
        return "modify"
    return None


def action_kind(action: Mapping[str, Any]) -> str:
    """Semantic operation kind — the MAX severity of method, method-override,
    RPC action selector, and URL path tokens. Never below the method kind."""
    kinds = [_method_kind(str(action.get("method") or ""))]

    # headers arrive as a Mapping or a wire-style list of {name,value}/(k,v) pairs
    header_items: List[Tuple[str, str]] = []
    headers = action.get("headers")
    if isinstance(headers, Mapping):
        header_items = [(str(k), str(v)) for k, v in headers.items()]
    elif isinstance(headers, (list, tuple)):
        for h in headers:
            if isinstance(h, Mapping):
                header_items.append((str(h.get("name") or h.get("key") or ""),
                                     str(h.get("value") or "")))
            elif isinstance(h, (list, tuple)) and len(h) == 2:
                header_items.append((str(h[0]), str(h[1])))
    for k, v in header_items:
        if k.lower() in _METHOD_OVERRIDE_KEYS:
            kinds.append(_method_kind(v))

    for container in value_scanners._containers(action):
        for k, v in _iter_kv(container):
            lk = k.lower()
            if lk in _METHOD_OVERRIDE_KEYS:
                kinds.append(_method_kind(v))
            elif lk in _ACTION_FIELD_KEYS:
                # 2026-08-07 review I4：selector 值同样过多轮 percent-decode——
                # form 编码 body 服务端会解码，%64%65%6c%65%74%65 不能藏住 delete。
                # 注（I3 权衡）：键名单已扩充（func/task/handler/mode/event/...）；
                # "任意键 + 值精确等值"兜底方案被放弃——{"name":"delete"} 类正常字段会误伤。
                for lv in _decode_variants(v):
                    if any(t in lv for t in _DELETE_TOKENS):
                        kinds.append("delete")
                        break
                    if any(t in lv for t in _MODIFY_TOKENS):
                        kinds.append("modify")
                        break

    pk = _path_kind(action)
    if pk:
        kinds.append(pk)
    return max(kinds, key=lambda k: _SEVERITY[k])


def refine(
    action: Mapping[str, Any],
    base_grade: str,
    base_decision: str,
    base_reasons: Optional[list] = None,
    *,
    inert: Optional[InertSurface] = None,
    ledger_path: Optional[str] = None,
) -> Dict[str, Any]:
    grade = str(base_grade or "A0")
    decision = str(base_decision or "need_human")
    reasons = list(base_reasons or [])
    rule = "base"
    kind = action_kind(action)
    scan = value_scanners.scan(action)

    def to_human(reason: str) -> None:
        nonlocal decision, rule
        if decision != "forbid":  # never weaken a forbid
            decision, rule = "need_human", reason
            if reason not in reasons:
                reasons.append(reason)

    # 1) forbid is terminal — nothing below can relax it.
    if decision == "forbid" or grade == "F0":
        return {"decision": "forbid", "grade": grade, "reasons": reasons, "rule": "base_forbid", "kind": kind, "scan": scan}

    # A method-only base grader may allow GET while semantic analysis finds a
    # write (for example /reset). Do not let that bypass the ownership checks.
    if kind in ("create", "modify", "other"):
        to_human("write_or_unknown_requires_operator_proof")

    # 2) dangerous signals on any create/modify -> force human (can only raise).
    dangerous = False
    if kind in ("create", "modify", "other"):
        if scan["url_or_callback"]:
            to_human("create_registers_server_side_egress"); dangerous = True   # SSRF/exfil, escapes netns (add-abuse-3)
        if scan["privilege_or_credential"]:
            to_human("privilege_or_credential_write"); dangerous = True          # add-abuse-5
        if scan["cleanup_keyword"]:
            to_human("irreversible_side_effect_surface"); dangerous = True        # payment/sms/state (add-abuse-4)

    # 3) delete is always human.
    if kind == "delete":
        to_human("delete_requires_human")
        return {"decision": decision, "grade": grade, "reasons": reasons, "rule": rule, "kind": kind, "scan": scan}

    # 4) NARROW auto-allow carve-out — only converts a clean base need_human.
    if decision == "need_human" and not dangerous:
        if kind == "create" and inert is not None:
            if inert.endpoint_is_inert(action) and inert.writes_provisioned_principal(action):
                decision, rule = "allow_limited", "benign_inert_surface_create"
                reasons.append(f"inert_surface_sig={inert.signature_status}")
            else:
                to_human("create_not_on_operator_inert_allowlist")
        elif kind == "modify":
            if scan["shared_state"]:
                to_human("modify_touches_shared_state")                           # modify-self-3
            elif ledger_path:
                owned, why = is_owned_strict(
                    ledger_path,
                    target_id=str(action.get("target_id") or ""),
                    resource_id=str(action.get("resource_id") or ""),
                    collection=str(action.get("collection") or ""),
                    tenant=str(action.get("tenant") or ""),
                    current_fingerprint=str(action.get("current_fingerprint") or ""),
                )
                if owned:
                    decision, rule = "allow_limited", "modify_self_created_proven"
                else:
                    to_human(f"modify_not_proven_self_created:{why}")
            else:
                to_human("modify_no_ledger_configured")

    return {"decision": decision, "grade": grade, "reasons": reasons, "rule": rule, "kind": kind, "scan": scan}
