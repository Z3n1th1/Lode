"""One admission decision for every request that may leave the process.

Why this module exists, in one paragraph: ``method`` cannot tell a read from a write.
``POST /search`` reveals routes; ``POST /logout`` and ``POST /api/items`` change state
with no body at all; ForgeRock's ``?action=validateGoto`` is a read that only answers
to POST. A rule as coarse as "GET/HEAD or nothing" under-serves the product, and a rule
as coarse as "POST is fine" is how a tool deletes someone's production data. So the
probe tier is **deny by default**: a non-read request goes out only when it can
*positively prove* it is a read, and everything unrecognised is refused.

The policy this module encodes is deliberately stricter than
``guardrails.guardrails.action_policy`` — it borrows that module's **classifier**
(``action_kind`` + ``value_scanners``), not its policy. ``refine`` is built around an
operator-proof workflow whose only relaxation lane needs an ``InertSurface`` allowlist
and a MAC-bound ledger, neither of which exists on this path; and its human gate
(``guardrails.tools.human_gate``) always answers
``hard_blocked:approval_authority_unconfigured``, so there is **no locally reachable
way to approve anything**. "Needs a human" therefore means "refused" here, and the
audit row says so.

Reason codes mirror the guardrails rule names on purpose, so the two layers do not
drift into two vocabularies for the same finding.
"""
from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple
from urllib.parse import parse_qsl

from core.src_blackboard import read_operation_selector, state_changing_reason

# The read path. These never touch the scanner below — see ``admit``.
READ_METHODS = frozenset({"GET", "HEAD"})
# The probe tier: candidates for a non-mutating request. PUT/PATCH are here so that a
# refusal can name *why* (``update_semantics``) instead of shrugging ``method_not_allowed``.
PROBE_METHODS = frozenset({"OPTIONS", "POST", "PUT", "PATCH"})
#: Probe-tier methods that are *by their own semantics* an update, so no request carried
#: by them is ever admitted. Named separately from ``PROBE_METHODS`` because that set
#: answers "what may be declared" and this one answers "what may ever go out" — the
#: prompt and the console both need the second question, and neither should hardcode it.
UPDATE_METHODS = frozenset({"PUT", "PATCH"})
#: Every method this gate can, in principle, let through. The capability line the model
#: reads is built from this, so it can never advertise a verb the gate would refuse.
ADMISSIBLE_METHODS = (READ_METHODS | PROBE_METHODS) - UPDATE_METHODS
# Not in the vocabulary at all (``agents.surface_discovery._METHOD_ORDER``), and refused
# again here so the audit trail says which of the two happened.
DESTRUCTIVE_METHODS = frozenset({"DELETE"})

# Reason codes.
DESTRUCTIVE_METHOD = "destructive_method_forbidden"
NOT_PROVEN = "probe_not_proven_non_mutating"
CLASSIFIER_UNAVAILABLE = "admission_classifier_unavailable"
NOT_IN_PROBE_TIER = "method_not_in_probe_tier"

_GQL_PATH_TOKENS = ("graphql", "graphiql", "gql")
_GQL_ALLOWED_KEYS = frozenset({"query", "operationname", "variables"})
# GraphQL only leaves the read operation off the wire when the document says
# ``mutation``/``subscription``; a word-boundary test is therefore sound for the
# operation *type*. (A server may still implement an effectful field as a query field —
# that is a broken server, and the budget + audit are the mitigation, not more regex.)
_GQL_NON_READ = re.compile(r"\b(mutation|subscription)\b", re.IGNORECASE)


@dataclass(frozen=True)
class Verdict:
    """Allowed, or refused with a reason the operator can act on."""

    allowed: bool
    reason: str = ""
    tier: str = "read"
    detail: Dict[str, Any] = field(default_factory=dict)


def _allow(tier: str, **detail: Any) -> Verdict:
    return Verdict(True, "", tier, detail)


def _refuse(reason: str, tier: str, **detail: Any) -> Verdict:
    return Verdict(False, reason, tier, detail)


# ---------------------------------------------------------------------------
# The semantic classifier (lazily imported, fail-closed)
# ---------------------------------------------------------------------------

_GUARDRAILS: Optional[Tuple[Any, Any, str]] = None


def _guardrails() -> Tuple[Any, Any, str]:
    """``(action_policy, value_scanners, error)`` — cached; error is ``""`` on success.

    Imported the same way ``notify/task_router.py`` does it: insert the package root on
    ``sys.path``. It is stdlib-only apart from the optional ``inert_surface`` bits we do
    not touch, so this adds no real dependency.
    """
    global _GUARDRAILS
    if _GUARDRAILS is None:
        try:
            root = Path(__file__).resolve().parents[1] / "guardrails-mcp"
            if str(root) not in sys.path:
                sys.path.insert(0, str(root))
            from guardrails import action_policy, value_scanners  # type: ignore

            _GUARDRAILS = (action_policy, value_scanners, "")
        except Exception as exc:  # noqa: BLE001 - an optional dependency
            _GUARDRAILS = (None, None, f"{type(exc).__name__}: {str(exc)[:120]}")
    return _GUARDRAILS


def classifier_available() -> bool:
    action_policy, value_scanners, _error = _guardrails()
    return action_policy is not None and value_scanners is not None


def classifier_error() -> str:
    return _guardrails()[2]


# ---------------------------------------------------------------------------
# The request card the classifier reads
# ---------------------------------------------------------------------------

def _parse_container(body: str, content_type: str) -> Optional[Any]:
    """The body as a mapping, or ``None`` when it is not one.

    Without this the classifier's body coverage is an illusion: ``action_kind`` walks
    *containers* and yields nothing for a ``str``, so ``action=delete`` sent as a form
    body would sail past the selector escalation. Parse before classifying.
    """
    text = (body or "").strip()
    if not text:
        return None
    lowered = (content_type or "").lower()
    form_shaped = "json" in lowered or text[:1] in ("{", "[")
    if form_shaped:
        try:
            parsed = json.loads(text)
        except (ValueError, TypeError):
            parsed = None
        if isinstance(parsed, (dict, list)):
            return parsed
    if "json" in lowered:
        return None
    if text[:1] in ("{", "["):
        return None
    try:
        pairs = parse_qsl(text, keep_blank_values=True)
    except ValueError:
        return None
    return dict(pairs) if pairs else None


def build_action_card(method: str, url: str, body: str = "",
                      content_type: str = "") -> Dict[str, Any]:
    """The shape ``guardrails`` classifies. Contains no credentials by construction."""
    container = _parse_container(body, content_type)
    card: Dict[str, Any] = {"method": method, "url": url, "headers": {}}
    if body:
        card["body"] = body
    if isinstance(container, dict):
        card["form"] = container
        if "json" in (content_type or "").lower() or (body or "").strip()[:1] in ("{", "["):
            card["json"] = container
    return card


# ---------------------------------------------------------------------------
# The decision
# ---------------------------------------------------------------------------

def admit(*, method: str, url: str, body: str = "", content_type: str = "") -> Verdict:
    """Allowed, or refused with a reason. Pure; no network, no I/O.

    Gate order is the point, and the caller runs this *after* the scope check, the
    method-declaration check and the body-declaration check, so this function is the
    fifth gate and the last one before the request budget.
    """
    verb = str(method or "GET").strip().upper() or "GET"

    if verb in DESTRUCTIVE_METHODS:
        # Checked before anything else so the audit names the real reason rather than
        # a generic "method not allowed". Defence in depth: DELETE is also absent from
        # the declaration vocabulary, so a document cannot ask for it either.
        return _refuse(DESTRUCTIVE_METHOD, "read", method=verb)

    if verb in READ_METHODS:
        return _admit_read(verb, url)

    tier = "probe"
    if verb not in PROBE_METHODS:
        return _refuse(NOT_IN_PROBE_TIER, tier, method=verb)

    # Guards first. ``state_changing_reason`` runs before the word list, so
    # ``?_method=DELETE`` lands in the selector branch rather than being read as
    # "the URL mentions delete". No declaration buys past either of these.
    read_reason = state_changing_reason(url)
    if read_reason == "unknown_operation_selector":
        return _refuse("unknown_operation_selector", tier, method=verb)
    if read_reason:
        return _refuse("state_changing_endpoint", tier, method=verb)

    action_policy, value_scanners, error = _guardrails()
    if action_policy is None or value_scanners is None:
        # Fail closed: the widening is unavailable, the read path is untouched, and the
        # run is not aborted. Never fail open here.
        return _refuse(CLASSIFIER_UNAVAILABLE, tier, method=verb, error=error)

    card = build_action_card(verb, url, body, content_type)
    try:
        kind = action_policy.action_kind(card)
        scan = value_scanners.scan(card)
    except Exception as exc:  # noqa: BLE001 - a broken classifier must not open the gate
        return _refuse(CLASSIFIER_UNAVAILABLE, tier, method=verb,
                       error=f"{type(exc).__name__}: {str(exc)[:120]}")

    if kind == "delete":
        return _refuse("mutating_request_refused:delete", tier, method=verb, kind=kind)
    if kind == "modify":
        return _refuse("mutating_request_refused:update_semantics", tier, method=verb, kind=kind)
    # The one signal that stays a hard gate even for a proven read: a URL-valued
    # parameter makes the *target* fetch a third party, and no scope gate can see where
    # that lands (红线 8: 禁止对第三方服务、外部 API 连带测试).
    if scan.get("url_or_callback"):
        return _refuse("mutating_request_refused:server_side_egress", tier, method=verb, kind=kind)

    # Now the request has to *prove* it is a read. Note what is deliberately NOT checked
    # above: ``privilege_or_credential`` / ``cleanup_keyword`` / ``shared_state``.
    #
    # Those three answer "would *changing* this be dangerous?" — they trip on the URL's
    # shape, not on our request's effect. ``_PRIV_ENDPOINT_RE`` matches ``/users?``, so
    # any user-admin endpoint trips it; ``_SHARED_HINTS`` contains ``config`` / ``group`` /
    # ``role``; ``_CLEANUP_HINTS`` contains ``order`` / ``notify``. Applying them to reads
    # refuses ``OPTIONS /openidm/config/managed`` (RFC-safe, zero side effects) and
    # ``POST /openidm/managed/user?_action=validateGoto`` — measured on a real target
    # 2026-09-21, which is how this ordering was found. Reading a sensitive surface is the
    # hunt's whole job; ``guardrails.action_policy.refine`` only consults these scanners
    # for create/modify/other for exactly this reason.
    proof = _read_proof(verb, url, body)
    if proof:
        return _allow(tier, method=verb, proof=proof)

    # Not proven. The remaining signals now only choose which reason to show the model,
    # so the refusal is actionable instead of a shrug.
    for signal, label in (("privilege_or_credential", "privilege_or_credential"),
                          ("cleanup_keyword", "irreversible_surface"),
                          ("shared_state", "shared_state")):
        if scan.get(signal):
            return _refuse(f"{NOT_PROVEN}:{label}", tier, method=verb, kind=kind)
    return _refuse(NOT_PROVEN, tier, method=verb, kind=kind)


def _read_proof(verb: str, url: str, body: str) -> str:
    """``"options"`` / ``"read_selector"`` / ``"graphql_query"``, or ``""`` for no proof.

    Three shapes and nothing else, each of which says on its face what it does:
    ``OPTIONS`` cannot mutate by spec; a read operation selector is the endpoint
    declaring its own operation; a GraphQL ``query`` needs the literal keyword
    ``mutation`` to be anything else. An empty body is **not** on this list — ``POST
    /logout`` and ``POST /api/items`` both mutate without one.
    """
    if verb == "OPTIONS":
        return "" if body else "options"
    if verb == "POST":
        if read_operation_selector(url):
            return "read_selector"
        if _graphql_read(url, body):
            return "graphql_query"
    return ""


def _admit_read(verb: str, url: str) -> Verdict:
    """The read path.

    Deliberately *not* routed through ``value_scanners``: it flags any parameter whose
    value looks like a URL (``?url=https://…``) as server-side egress, and any mention
    of ``config``/``settings``/``order`` as shared state — which is to say it refuses
    ``GET /api/orders``, the product's single most common read. The token-set heuristic
    below is weaker on purpose; that is the right trade for reads.

    The one tightening over the previous policy: a state-changing-looking URL is refused
    **unconditionally**. Declaring a write method used to downgrade this to a warning,
    which let ``GET /logout`` and ``GET /api/deleteUser`` through — and "禁止任何增删改
    数据/配置的写操作" is written in terms of what the operation *does*, not which verb
    carries it.
    """
    reason = state_changing_reason(url)
    if reason == "unknown_operation_selector":
        return _refuse("unknown_operation_selector", "read", method=verb)
    if reason:
        return _refuse("state_changing_endpoint", "read", method=verb)
    return _allow("read", method=verb)


def _graphql_read(url: str, body: str) -> bool:
    """A GraphQL *query*, proven from the wire shape. All conditions must hold."""
    lowered = str(url or "").lower()
    if not any(token in lowered for token in _GQL_PATH_TOKENS):
        return False
    try:
        parsed = json.loads(body or "")
    except (ValueError, TypeError):
        return False
    if not isinstance(parsed, dict):
        return False
    keys = {str(key).lower() for key in parsed}
    if "query" not in keys or not keys <= _GQL_ALLOWED_KEYS:
        return False
    return _GQL_NON_READ.search(json.dumps(parsed, ensure_ascii=False)) is None


__all__ = [
    "CLASSIFIER_UNAVAILABLE", "DESTRUCTIVE_METHOD", "DESTRUCTIVE_METHODS",
    "NOT_IN_PROBE_TIER", "NOT_PROVEN", "PROBE_METHODS", "READ_METHODS",
    "Verdict", "admit", "build_action_card", "classifier_available", "classifier_error",
]
