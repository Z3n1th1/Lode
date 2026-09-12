"""Small, deterministic score corrections before a finding is broadcast."""
from __future__ import annotations

from typing import Any, Dict


_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_COMPARATIVE_EVIDENCE = {
    "L2_differential_pair",
    "L3_reproducible_impact",
    "L4_independent_reproduction",
}
_FRONTEND_CRYPTO_TYPES = {
    "frontend_crypto_key",
    "frontend_crypto_material",
    "client_side_crypto_key",
}


def _normalize_severity(value: object) -> str:
    severity = str(value or "low").lower().strip()
    return severity if severity in _SEVERITY_RANK else "low"


def _append_reason(existing: object, addition: str) -> str:
    previous = str(existing or "").strip()
    return f"{previous}；{addition}" if previous else addition


def _is_frontend_crypto_material(finding: Dict[str, Any]) -> bool:
    finding_type = str(finding.get("type", "")).lower().strip()
    if finding_type in _FRONTEND_CRYPTO_TYPES:
        return True
    title = str(finding.get("title", "")).lower()
    return "前端" in title and any(token in title for token in ("密钥", "key", "crypto", "加密"))


def score_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Return a scored copy without converting an observation into an impact claim.

    Client-visible crypto material is a low-severity clue unless a separate finding
    proves server-side impact.  High and critical findings require both comparative
    evidence and a positive Verifier result before retaining their claimed level.
    """
    result = dict(finding)
    severity = _normalize_severity(result.get("severity"))

    if _is_frontend_crypto_material(result):
        result["severity"] = "low"
        result["reason"] = _append_reason(
            result.get("reason"),
            "前端可见的加密材料本身不证明服务端影响，按低危线索记录",
        )
        return result

    if _SEVERITY_RANK[severity] >= _SEVERITY_RANK["high"]:
        verified = result.get("verified") is True or result.get("verifier_status") == "confirmed"
        if not verified:
            result["severity"] = "medium"
            result["reason"] = _append_reason(
                result.get("reason"),
                "高危以上结论缺少 Verifier 确认，先按中危候选处理",
            )
            return result
        if result.get("evidence_level") not in _COMPARATIVE_EVIDENCE:
            result["severity"] = "medium"
            result["reason"] = _append_reason(
                result.get("reason"),
                "高危以上结论缺少可复现的对比证据，先按中危候选处理",
            )
            return result

    result["severity"] = severity
    result["reason"] = _append_reason(result.get("reason"), "评分保留，影响与证据条件匹配")
    return result
