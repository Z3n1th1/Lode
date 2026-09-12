"""Regressions for the 2026-08-07 core review findings (each was a real bug/hole
in the concurrent hardening; these lock the fixes)."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

_GMCP = Path(__file__).resolve().parents[1]
if str(_GMCP) not in sys.path:
    sys.path.insert(0, str(_GMCP))

from guardrails.tools import policy_grade  # noqa: E402
from guardrails import hardened_ledger  # noqa: E402

ALLOWLIST = str(_GMCP / "config" / "inert_surface_allowlist.example.yaml")
INERT = "https://staging.example.com/api/qa/notes"       # on operator allowlist
PRINCIPAL = "qa-sandbox-user-1"


def _seed(tmp_path, rid="obj-1", fp="fp-1"):
    ledger = str(tmp_path / "created.json")
    hardened_ledger.record_created(
        ledger, target_id="t1", resource_id=rid, resource_kind="note",
        collection="notes", tenant="tenantA", source_action_digest="a" * 64,
        server_fingerprint=fp, server_minted=True, proven_new=True)
    return ledger


# --- HIGH #1: camelCase / CJK delete route must NOT auto-allow as a create ---

def test_camelcase_delete_route_on_allowlist_gates_not_autoallow():
    res = policy_grade({"action_id": "a", "method": "POST",
                        "url": INERT + "/deleteItem", "account_alias": PRINCIPAL,
                        "body": {"note": "x"}}, inert_allowlist_path=ALLOWLIST)
    assert res["decision"] == "need_human"          # was allow_limited before fix
    assert res["kind"] == "delete"


def test_cjk_delete_route_on_allowlist_gates(tmp_path):
    res = policy_grade({"action_id": "a", "method": "POST",
                        "url": INERT + "/%E5%88%A0%E9%99%A4",  # 删除 (url-encoded)
                        "account_alias": PRINCIPAL, "body": {"note": "x"}},
                       inert_allowlist_path=ALLOWLIST)
    assert res["decision"] == "need_human"


# --- HIGH #2: ledger fail-CLOSED when no HMAC key (forgeable ledger) ---

def test_modify_self_fails_closed_without_hmac_key(tmp_path, monkeypatch):
    monkeypatch.delenv("GUARDRAILS_LEDGER_HMAC_KEY", raising=False)
    ledger = _seed(tmp_path)  # row recorded unsigned (no key)
    res = policy_grade({"action_id": "m", "method": "PUT", "url": "https://t/api/notes/obj-1",
                        "target_id": "t1", "resource_id": "obj-1", "collection": "notes",
                        "tenant": "tenantA", "current_fingerprint": "fp-1",
                        "body": {"note": "edit"}},
                       inert_allowlist_path=ALLOWLIST, ledger_path=ledger)
    assert res["decision"] == "need_human"
    assert any("hmac_key_unconfigured" in r for r in res["reasons"])


# --- #8: malformed ledger row must not crash the gate (fail-open) ---

def test_malformed_ledger_row_does_not_crash(tmp_path, monkeypatch):
    monkeypatch.setenv("GUARDRAILS_LEDGER_HMAC_KEY", "k")
    ledger = str(tmp_path / "bad.json")
    Path(ledger).write_text(json.dumps({"schema": "HardenedCreatedResourceLedger/v1",
        "resources": ["this-is-not-a-mapping", 123, {"target_id": "t1"}]}), encoding="utf-8")
    # must return a decision (need_human), not raise
    res = policy_grade({"action_id": "m", "method": "PUT", "url": "https://t/api/notes/x",
                        "target_id": "t1", "resource_id": "x", "collection": "notes",
                        "tenant": "tenantA", "current_fingerprint": "f"},
                       inert_allowlist_path=ALLOWLIST, ledger_path=ledger)
    assert res["decision"] == "need_human"


# --- csrf_token must NOT force-gate a benign create (carve-out usable again) ---

def test_benign_create_with_csrf_token_still_auto_allows():
    res = policy_grade({"action_id": "a", "method": "POST", "url": INERT,
                        "account_alias": PRINCIPAL,
                        "body": {"note": "hi", "csrf_token": "abc123"}},
                       inert_allowlist_path=ALLOWLIST)
    assert res["decision"] == "allow_limited"       # was need_human before fix
    assert res["rule"] == "benign_inert_surface_create"


def test_benign_create_with_filter_all_value_still_auto_allows():
    # bare value 'all' is no longer a global privilege signal
    res = policy_grade({"action_id": "a", "method": "POST", "url": INERT,
                        "account_alias": PRINCIPAL, "body": {"note": "hi", "filter": "all"}},
                       inert_allowlist_path=ALLOWLIST)
    assert res["decision"] == "allow_limited"


# --- but a real role=admin in the body still gates (regression guard) ---

def test_role_admin_body_still_gates_on_allowlist():
    res = policy_grade({"action_id": "a", "method": "POST", "url": INERT,
                        "account_alias": PRINCIPAL, "body": {"note": "hi", "role": "admin"}},
                       inert_allowlist_path=ALLOWLIST)
    assert res["decision"] == "need_human"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
