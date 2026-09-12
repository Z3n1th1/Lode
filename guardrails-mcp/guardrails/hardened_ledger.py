"""Hardened CreatedResourceLedger (red-team modify-self / drift-audit-2).

The existing scripts/created_resources.py is a good MVP but the red team showed
its weaknesses: agent-writable plaintext, owner defaulting to 'SELF', and a bare
string-membership ownership test. This wrapper adds the trust layer required to
auto-allow a MODIFY of "our own" data:

  auto-modify-self is allowed ONLY when ALL hold —
    1. row exists for (target_id, resource_id)
    2. row MAC verifies (not forged) [prod: key required; dev: flagged]
    3. resource_id is server-minted AND proven-new at create
    4. (tenant, collection, id) identical between create and modify
    5. an immutable server fingerprint read-before-write still matches
  ...and action_policy separately requires NO shared-state semantics.
  Any missing element -> not owned -> human gate. "Cannot prove" == human gate.

Rows are appended ONLY by the gateway after a real executed create (never from a
card field). Physical tamper-resistance (separate uid, read-only to agent) is a
deploy-layer property; the MAC makes forgery detectable even before that.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

_MAC_FIELDS = ("target_id", "resource_id", "resource_kind", "collection",
               "tenant", "source_action_digest", "server_fingerprint",
               "server_minted", "proven_new", "created_at")


def _key() -> Optional[str]:
    return os.environ.get("GUARDRAILS_LEDGER_HMAC_KEY")


def _row_mac(row: Mapping[str, Any], key: str) -> str:
    body = {k: row.get(k) for k in _MAC_FIELDS}
    canon = json.dumps(body, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hmac.new(key.encode("utf-8"), canon, hashlib.sha256).hexdigest()


def _load(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    rows = data.get("resources") if isinstance(data, Mapping) else None
    # filter to Mapping rows so a malformed/hand-edited ledger (a string/int in
    # the list) cannot crash the gate — a crash on the load path is fail-OPEN.
    return [dict(r) for r in rows if isinstance(r, Mapping)] if isinstance(rows, list) else []


def _atomic_write(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = {"schema": "HardenedCreatedResourceLedger/v1", "resources": rows}
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def record_created(
    path: str,
    *,
    target_id: str,
    resource_id: str,
    resource_kind: str,
    collection: str,
    tenant: str,
    source_action_digest: str,
    server_fingerprint: str,
    server_minted: bool,
    proven_new: bool,
) -> Dict[str, Any]:
    """Append a create row (call ONLY from the gateway after a real create)."""
    p = Path(path)
    row: Dict[str, Any] = {
        "target_id": str(target_id), "resource_id": str(resource_id),
        "resource_kind": str(resource_kind), "collection": str(collection),
        "tenant": str(tenant), "source_action_digest": str(source_action_digest),
        "server_fingerprint": str(server_fingerprint),
        "server_minted": bool(server_minted), "proven_new": bool(proven_new),
        "created_at": "recorded",
    }
    key = _key()
    row["mac"] = _row_mac(row, key) if key else ""
    rows = _load(p)
    if not any(r.get("target_id") == row["target_id"] and r.get("resource_id") == row["resource_id"] for r in rows):
        rows.append(row)
        _atomic_write(p, rows)
    return {"recorded": True, "resource_id": row["resource_id"], "signed": bool(key)}


def is_owned_strict(
    path: str,
    *,
    target_id: str,
    resource_id: str,
    collection: str,
    tenant: str,
    current_fingerprint: str,
) -> Tuple[bool, str]:
    """All-or-nothing ownership proof for auto-modify-self. Returns (owned, reason)."""
    if not resource_id:
        return False, "no_resource_id"
    rows = _load(Path(path))
    match = next((r for r in rows if r.get("target_id") == str(target_id)
                  and r.get("resource_id") == str(resource_id)), None)
    if match is None:
        return False, "not_in_ledger"  # cannot prove self-created -> human gate
    key = _key()
    if not key:
        # FAIL-CLOSED: with no HMAC key the ledger is agent-forgeable (D2), so a
        # row cannot prove self-creation. Never auto-allow a modify unsigned —
        # the caller falls to the human gate. Prod MUST set GUARDRAILS_LEDGER_HMAC_KEY.
        return False, "ledger_hmac_key_unconfigured"
    expected = _row_mac(match, key)
    if not hmac.compare_digest(expected, str(match.get("mac") or "")):
        return False, "ledger_row_mac_invalid"  # forged/edited row
    if not match.get("server_minted"):
        return False, "id_not_server_minted"
    if not match.get("proven_new"):
        return False, "id_not_proven_new_at_create"
    if str(match.get("collection") or "") != str(collection or ""):
        return False, "collection_mismatch"
    if str(match.get("tenant") or "") != str(tenant or ""):
        return False, "tenant_mismatch"
    if not current_fingerprint or str(match.get("server_fingerprint") or "") != str(current_fingerprint):
        return False, "fingerprint_mismatch_or_missing"  # id-recycle / TOCTOU
    return True, "modify_self_proven"
