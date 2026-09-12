"""Operator-owned inert-surface allowlist (red-team add-abuse-1).

Auto-allowing a create is gated on an OPERATOR-owned allowlist of surfaces proven
inert out-of-band + writes into an operator-provisioned sandbox principal —
NEVER a model claim of "benign" and never a blacklist miss.

Trust model (same as scope / proxy whitelist / ledger):
- Operator-owned, agent READ-ONLY. Physically enforced on the VPS via a
  read-only bind mount owned by a separate uid (deploy layer).
- Optionally HMAC-signed: set env GUARDRAILS_CONFIG_HMAC_KEY (held outside the
  agent) and a top-level `hmac` field; unsigned configs are accepted only in dev
  and flagged, so a forged/edited allowlist is detectable.
"""
from __future__ import annotations

import fnmatch
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None

SCHEMA = "InertSurfaceAllowlist/v1"


def _load_raw(path: Path) -> Dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json" or yaml is None:
        return json.loads(text)
    return yaml.safe_load(text) or {}


def _canonical_for_sig(cfg: Mapping[str, Any]) -> bytes:
    body = {k: v for k, v in cfg.items() if k != "hmac"}
    return json.dumps(body, sort_keys=True, ensure_ascii=False).encode("utf-8")


def verify_signature(cfg: Mapping[str, Any]) -> str:
    """Return 'verified' | 'unsigned_dev' | 'invalid'. Invalid must fail closed."""
    key = os.environ.get("GUARDRAILS_CONFIG_HMAC_KEY")
    sig = str(cfg.get("hmac") or "")
    if not key:
        return "unsigned_dev"
    expected = hmac.new(key.encode("utf-8"), _canonical_for_sig(cfg), hashlib.sha256).hexdigest()
    return "verified" if hmac.compare_digest(expected, sig) else "invalid"


class InertSurface:
    def __init__(self, cfg: Mapping[str, Any], signature_status: str) -> None:
        self.cfg = dict(cfg)
        self.signature_status = signature_status
        self.inert_endpoints: List[Dict[str, str]] = list(cfg.get("inert_create_endpoints") or [])
        self.principals = {str(p) for p in (cfg.get("provisioned_test_principals") or [])}

    @property
    def trustworthy(self) -> bool:
        # In prod (key configured) only a verified signature is trusted.
        return self.signature_status in ("verified", "unsigned_dev")

    def endpoint_is_inert(self, action: Mapping[str, Any]) -> bool:
        if not self.trustworthy:
            return False
        method = str(action.get("method") or "").upper()
        url = str(action.get("url") or action.get("target") or "")
        for entry in self.inert_endpoints:
            em = str(entry.get("method") or "").upper()
            glob = str(entry.get("url_glob") or "")
            if (not em or em == method) and glob and fnmatch.fnmatch(url, glob):
                return True
        return False

    def writes_provisioned_principal(self, action: Mapping[str, Any]) -> bool:
        if not self.trustworthy or not self.principals:
            return False
        principal = str(action.get("account_alias") or action.get("session_alias")
                        or action.get("principal") or "")
        return principal in self.principals


def load(path: Optional[str]) -> InertSurface:
    """Load the allowlist; a missing/unreadable file yields an EMPTY surface
    (nothing auto-allows → everything falls to the human gate = fail-closed)."""
    if not path:
        return InertSurface({}, "missing")
    p = Path(path).expanduser()
    if not p.is_file():
        return InertSurface({}, "missing")
    try:
        cfg = _load_raw(p)
    except Exception:
        return InertSurface({}, "invalid")
    if not isinstance(cfg, Mapping):
        return InertSurface({}, "invalid")
    return InertSurface(cfg, verify_signature(cfg))
