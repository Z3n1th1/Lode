"""The 5 minimal guardrail tools (Phase-1 / walking-skeleton).

policy_grade + human_gate are fully implemented and unit-tested here.
gateway_request / record_evidence / verify_finding delegate to the reused
ai-pentest-matrix scripts (execution_kernel / evidence_indexer / verify_finding),
so the baseline loop `policy_grade -> gateway_request -> record_evidence ->
verify_finding` runs end-to-end on the real evidence layer.

Egress safety: gateway_request pre-gates via the hardened policy_grade, and
REFUSES to escalate to a live network request (execute=True) unless the
deploy-layer physical enforcement (netns + L7 MITM as the sole route) is
confirmed via GUARDRAILS_PHYSICAL_EGRESS_CONFIRMED=1. Without it, everything is
dry-run — no bare connect can happen from this dev slice.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from . import action_policy, scripts_bridge
from .inert_surface import load as load_inert

_ALLOW = {"allow", "allow_limited"}
_LIVE_EGRESS_ENV = "GUARDRAILS_PHYSICAL_EGRESS_CONFIRMED"
_MAX_REQUEST_BUDGET = 100
_LOCAL_FORBID = re.compile(
    r"(?i)(?:web\s*shell|reverse\s*shell|meterpreter|credential\s*(?:dump|theft)|"
    r"ransomware|cryptominer|勒索|反弹\s*shell|窃取凭据|rm\s+-rf|"
    r"(?:curl|wget)\s+\S+\s*\|\s*(?:sh|bash))"
)


def _default_root() -> Path:
    """Data root for evidence/ledgers. Override with PENTEST_AGENT_DATA."""
    env = os.environ.get("PENTEST_AGENT_DATA")
    return Path(env) if env else Path.cwd() / "data"


def _live_egress_confirmed() -> bool:
    """True only when the deploy layer has confirmed physical egress enforcement
    (netns + L7 MITM sole route). Dev/test defaults to False -> dry-run only."""
    return os.environ.get(_LIVE_EGRESS_ENV) == "1"


def _local_base_grade(action: Mapping[str, Any]):
    """Conservative standalone grade used when the private matrix is absent."""
    serialized = " ".join(
        str(value) for key, value in action.items()
        if key not in {"headers", "cookies"}
    )
    if _LOCAL_FORBID.search(serialized):
        return "F0", "forbid", ["standalone_explicitly_forbidden_payload"]
    method = str(action.get("method") or "GET").strip().upper()
    if method in {"GET", "HEAD", "OPTIONS"}:
        return "A0", "allow_limited", ["standalone_readonly_method"]
    return "H1", "need_human", ["standalone_write_or_unknown_requires_human"]


def _evaluate_base(action: Mapping[str, Any]):
    """Use the private matrix when present, otherwise a conservative local grade."""
    if not scripts_bridge.scripts_available():
        return _local_base_grade(action)
    import policy_engine  # type: ignore  # on sys.path via scripts_bridge
    res = policy_engine.evaluate_action(dict(action))
    grade = getattr(res, "risk_grade", None) or getattr(res, "grade", None) or "A0"
    decision = getattr(res, "decision", None) or "need_human"
    reasons = list(getattr(res, "reasons", None) or [])
    return str(grade), str(decision), reasons


def policy_grade(
    action: Mapping[str, Any],
    *,
    inert_allowlist_path: Optional[str] = None,
    ledger_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Grade an ActionCard: base evaluate_action + red-team-hardened refine.
    Returns {decision, grade, reasons, rule, kind, scan}."""
    grade, decision, reasons = _evaluate_base(action)
    inert = load_inert(inert_allowlist_path)
    return action_policy.refine(
        action, grade, decision, reasons, inert=inert, ledger_path=ledger_path
    )


def human_gate(need_human_card: Mapping[str, Any]) -> Dict[str, Any]:
    """Request human approval. FAIL-CLOSED (red-team drift-audit-6 / CLAUDE.md):
    no external attestation authority is wired, so no approval can be issued
    locally — delete/H2 are HARD-BLOCKED, not silently confirmable. Mirrors
    approval_decision.py. The real open path is an operator-key-signed
    ApprovalDecision verified against a public key baked into immutable config
    (deploy layer)."""
    return {
        "status": "hard_blocked",
        "reason": "approval_authority_unconfigured",
        "card": dict(need_human_card),
        "next_action": "issue an operator-signed external ApprovalDecision (deploy layer); "
                       "until configured this gate cannot be satisfied locally",
    }


def gateway_request(
    action: Mapping[str, Any],
    *,
    project_root: Optional[str] = None,
    execute: bool = False,
    request_budget: int = 1,
    inert_allowlist_path: Optional[str] = None,
    ledger_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Sole-egress request tool. Pre-gates via the hardened policy_grade; only
    allow/allow_limited may proceed to the reused execution_kernel pipeline
    (gateway_run + precheck verify). execute=True is silently downgraded to
    dry-run unless GUARDRAILS_PHYSICAL_EGRESS_CONFIRMED=1 (deploy-layer netns +
    L7 MITM must be the sole route) — no bare connect from the dev slice."""
    try:
        budget = int(request_budget)
    except (TypeError, ValueError):
        budget = 0
    if not 1 <= budget <= _MAX_REQUEST_BUDGET:
        return {
            "sent": False,
            "blocked": True,
            "decision": {"decision": "forbid", "grade": "F0",
                          "reasons": ["request_budget_out_of_range"],
                          "rule": "gateway_budget_guard"},
        }
    decision = policy_grade(action, inert_allowlist_path=inert_allowlist_path, ledger_path=ledger_path)
    if decision["decision"] not in _ALLOW:
        return {"sent": False, "blocked": True, "decision": decision}

    live_ok = _live_egress_confirmed()
    effective_execute = bool(execute) and live_ok

    if not scripts_bridge.scripts_available():
        return {
            "sent": False, "blocked": False, "decision": decision, "kernel": None,
            "execute_requested": bool(execute), "execute_effective": False,
            "live_egress_confirmed": live_ok,
            "note": "reused execution_kernel unavailable; dry-run only (fail-closed)",
        }

    root = Path(project_root) if project_root else _default_root()
    target_id = str(action.get("target_id") or action.get("target") or "unknown")
    # Fail-closed: if the reused kernel is unavailable or errors (e.g. a platform
    # portability gap), nothing is sent and the error is surfaced — never a crash
    # and never a silent live request.
    try:
        import execution_kernel  # type: ignore  # on sys.path via scripts_bridge
        kernel = execution_kernel.execute_pipeline(
            root, target_id, dict(action), execute=effective_execute, request_budget=budget
        )
    except Exception as exc:  # noqa: BLE001 - fail-closed on any kernel failure
        return {
            "sent": False, "blocked": False, "decision": decision,
            "execute_requested": bool(execute), "execute_effective": False,
            "live_egress_confirmed": live_ok, "kernel": None,
            "kernel_error": f"{type(exc).__name__}: {exc}",
        }
    return {
        "sent": bool(effective_execute),
        "blocked": False,
        "decision": decision,
        "execute_requested": bool(execute),
        "execute_effective": effective_execute,
        "live_egress_confirmed": live_ok,
        "kernel": kernel,
    }


def record_evidence(
    evidence: Mapping[str, Any],
    *,
    project_root: Optional[str] = None,
) -> Dict[str, Any]:
    """Record a request/response evidence pair into the reused verifier evidence
    layout (evidence_indexer.record_http_exchange). A bound pair is written when
    response_text + status_code are present and there is no transport error.
    Returns the evidence_dir that verify_finding() consumes. Fail-closed if the
    reused evidence layer is unavailable."""
    if not scripts_bridge.scripts_available():
        return {"recorded": False, "reason": "evidence_layer_unavailable_fail_closed"}

    import evidence_indexer  # type: ignore
    root = Path(project_root) if project_root else _default_root()
    target_id = str(evidence.get("target_id") or "unknown")
    finding_id = str(evidence.get("finding_id") or "unknown")
    # Ensure the finding dir/scaffold exists before appending the exchange.
    evidence_indexer.init_finding(
        root, target_id, finding_id,
        target=str(evidence.get("target") or ""),
        hypothesis_id=str(evidence.get("hypothesis_id") or ""),
        action_id=str((evidence.get("action") or {}).get("action_id") or ""),
    )
    status_code = evidence.get("status_code")
    # Integrity/scope rejections (unbound decision, out-of-scope host, malformed
    # card) are surfaced as recorded:False — the evidence layer refusing to record
    # a fabricated/mismatched exchange is expected, not a crash.
    try:
        _scope_err = getattr(__import__("target_scope"), "TargetScopeError", None)
    except Exception:  # pragma: no cover - target_scope always present with scripts
        _scope_err = None
    _reject = (ValueError,) + ((_scope_err,) if _scope_err else ())
    try:
        res = evidence_indexer.record_http_exchange(
            root, target_id, finding_id,
            dict(evidence.get("action") or {}),
            dict(evidence.get("decision") or {}),
            str(evidence.get("request_text") or ""),
            response_text=str(evidence.get("response_text") or ""),
            status_code=(int(status_code) if status_code is not None else None),
            error=str(evidence.get("error") or ""),
            target_card=evidence.get("target_card"),
            approval_record=evidence.get("approval_record"),
        )
    except _reject as exc:
        return {"recorded": False, "reason": f"{type(exc).__name__}: {exc}"}
    return {
        "recorded": True,
        "evidence_dir": str(res.get("evidence_dir")),
        "run_id": res.get("run_id"),
        "pair": res.get("pair"),
        "finding": res.get("finding"),
    }


def verify_finding(evidence_dir: str, **kwargs: Any) -> Dict[str, Any]:
    """Independent second-review (MoA aggregator). Delegates to the reused
    verify_finding.verify. Must run on a DIFFERENT model than the executor
    (model_policy, deploy layer)."""
    if not scripts_bridge.scripts_available():
        return {"status": "needs_more_evidence", "reason": "verifier_unavailable_fail_closed"}
    import verify_finding as vf  # type: ignore
    from pathlib import Path
    return vf.verify(Path(evidence_dir), **kwargs)


TOOLS = {
    "policy_grade": policy_grade,
    "gateway_request": gateway_request,
    "human_gate": human_gate,
    "record_evidence": record_evidence,
    "verify_finding": verify_finding,
}
