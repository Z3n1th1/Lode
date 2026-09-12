"""End-to-end baseline loop: policy_grade -> gateway_request(dry-run) ->
record_evidence -> verify_finding, wired to the REAL reused ai-pentest-matrix
scripts (execution_kernel / evidence_indexer / verify_finding). No network:
gateway_request stays dry-run (no GUARDRAILS_PHYSICAL_EGRESS_CONFIRMED), and the
evidence pair is a synthetic exchange fed straight into the evidence layer.

These prove the tools are no longer inert stubs and the loop runs on real
evidence, while the egress stays fail-closed (no bare connect)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_GMCP = Path(__file__).resolve().parents[1]
if str(_GMCP) not in sys.path:
    sys.path.insert(0, str(_GMCP))

from guardrails import scripts_bridge  # noqa: E402
from guardrails.tools import gateway_request, record_evidence, verify_finding  # noqa: E402

ALLOWLIST = str(_GMCP / "config" / "inert_surface_allowlist.example.yaml")
HOST = "t.example.com"

pytestmark = pytest.mark.skipif(
    not scripts_bridge.scripts_available(),
    reason="reused ai-pentest-matrix scripts not on path",
)


def _seed_target(root, target_id="t1", host=HOST):
    """A canonical, in-scope TargetCard must exist before any request/evidence
    (scope enforcement — mirrors the real 'authorize the target first' flow)."""
    import target_init  # type: ignore  # on sys.path via scripts_bridge
    target_init.init_target(Path(root), target_id, allowed_hosts=[host],
                            profile="standard-pentest", overwrite=True)


def _action(action_id, method, path, target_id="t1", finding_id="f1"):
    """A valid ActionCard/v1 (additionalProperties:false — exact fields only)."""
    return {
        "schema": "ActionCard/v1",
        "action_id": action_id,
        "target_id": target_id,
        "finding_id": finding_id,
        "method": method,
        "url": "https://" + HOST + path,
        "profile": "standard-pentest",
        "intent": "readonly baseline probe",
        "authorized_hosts": [HOST],
    }


def _decision_for(root, action):
    """The real, digest-bound PolicyDecision the gateway would issue for this
    action (dry-run, no network) — evidence integrity requires this binding."""
    import request_gateway  # type: ignore
    summary = request_gateway.gateway_run(
        dict(action), Path(root), dry_run=True, approved=False,
        timeout=2, max_response_bytes=4096,
    )
    return summary["decision"]


def _synthetic_evidence(tmp_path, target_id="t1", finding_id="f1"):
    action = _action("ACT-BL-1", "GET", "/app.js", target_id, finding_id)
    decision = _decision_for(tmp_path, action)
    return {
        "target_id": target_id, "finding_id": finding_id,
        "action": action, "decision": decision,
        "request_text": "GET /app.js HTTP/1.1\r\nHost: t.example.com\r\n\r\n",
        "response_text": "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\nvar a=1;",
        "status_code": 200,
    }


# --- egress fail-closed: a gated action never reaches the kernel ---

def test_blocked_action_does_not_reach_kernel(tmp_path):
    res = gateway_request(
        _action("ACT-DEL", "DELETE", "/api/users/1"),
        project_root=str(tmp_path), inert_allowlist_path=ALLOWLIST,
    )
    assert res["blocked"] is True
    assert res["decision"]["decision"] == "need_human"
    assert "kernel" not in res            # pre-gate blocked before delegation


def test_request_budget_is_bounded_before_kernel(tmp_path):
    res = gateway_request(
        _action("ACT-RD", "GET", "/app.js"),
        project_root=str(tmp_path), request_budget=101,
        inert_allowlist_path=ALLOWLIST,
    )
    assert res["blocked"] is True
    assert res["decision"]["decision"] == "forbid"
    assert "request_budget_out_of_range" in res["decision"]["reasons"]


# --- execute=True is downgraded to dry-run without physical egress confirmation ---

def test_execute_true_downgraded_without_physical_confirm(tmp_path, monkeypatch):
    monkeypatch.delenv("GUARDRAILS_PHYSICAL_EGRESS_CONFIRMED", raising=False)
    _seed_target(tmp_path)
    res = gateway_request(
        _action("ACT-RD", "GET", "/app.js"),
        project_root=str(tmp_path), execute=True, inert_allowlist_path=ALLOWLIST,
    )
    # regardless of base grade, live egress must not happen
    assert res.get("sent") in (False, None)
    if not res.get("blocked"):
        assert res["execute_requested"] is True
        assert res["execute_effective"] is False
        assert res["live_egress_confirmed"] is False
        # egress safe either way: the kernel ran (real ExecutionKernelResult) OR
        # was unavailable and we failed closed (kernel_error, nothing sent)
        kernel = res.get("kernel")
        if kernel is not None:
            assert kernel.get("schema") == "ExecutionKernelResult/v1" or "exit_code" in kernel
        else:
            assert "kernel_error" in res


# --- record_evidence writes a real verifier evidence pair to disk ---

def test_record_evidence_writes_pair(tmp_path):
    _seed_target(tmp_path)
    out = record_evidence(_synthetic_evidence(tmp_path), project_root=str(tmp_path))
    assert out["recorded"] is True
    ev = Path(out["evidence_dir"])
    assert ev.is_dir()
    assert list(ev.glob("requests/*.txt")), "no request artifact written"
    assert list(ev.glob("responses/*.txt")), "no response artifact written"
    assert (ev / "finding.yaml").exists()


# --- record_evidence is wired to the real integrity layer (not a blind stub) ---

def test_record_evidence_rejects_unbound_decision(tmp_path):
    _seed_target(tmp_path)
    ev = _synthetic_evidence(tmp_path)
    ev["decision"] = {"schema": "PolicyDecision/v1", "action_id": "ACT-BL-1",
                      "decision": "allow_limited", "risk_grade": "B0"}  # no action_digest
    out = record_evidence(ev, project_root=str(tmp_path))
    assert out["recorded"] is False
    assert "mismatch" in out["reason"] or "digest" in out["reason"]


# --- full loop: evidence -> independent verify runs on real evidence ---

def test_full_loop_record_then_verify(tmp_path):
    _seed_target(tmp_path)
    out = record_evidence(_synthetic_evidence(tmp_path), project_root=str(tmp_path))
    assert out["recorded"] is True
    result = verify_finding(out["evidence_dir"])
    # real verifier (not the old stub), and it correctly demands more evidence
    # (no impact_assertion) / precheck cannot self-confirm
    assert result.get("schema") == "VerifierResult/v1"
    assert "integrity_status" in result
    assert result["status"] == "needs_more_evidence"
    assert result.get("recommend_report") in (False, None)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
