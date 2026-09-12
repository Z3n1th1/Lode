#!/usr/bin/env python3
"""Canonical operation-profile selection for the pentest control plane.

The profile names and aliases are read from the repository's canonical registry.
Runtime policy stays deliberately small: choosing a profile is deterministic, and a
new target is held for an explicit profile choice unless the request already names
one.  Explicitly limited traffic analysis is the only /goal exception.
"""
from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple

try:
    import yaml
except Exception:  # pragma: no cover - covered by existing runtime dependency checks.
    yaml = None


_REGISTRY_PATH = (
    Path(__file__).resolve().parents[2]
    / "skills"
    / "ai-pentest-matrix"
    / "references"
    / "profiles"
    / "operation-profile-registry.yaml"
)

# The canonical registry normally lives in the sibling skills checkout.  The
# runtime is also distributed as a standalone project/zip, so importing the
# control plane must not depend on that checkout (or on PyYAML) being present.
# Keep this fallback intentionally small and schema-compatible with the
# canonical registry; a checked-out registry still wins when available.
_FALLBACK_REGISTRY_PROFILES: Dict[str, Dict[str, Any]] = {
    "standard-pentest": {
        "aliases": [],
        "completion_scope": "full_endpoint_assessment",
        "coverage_policy": {
            "endpoint_coverage_objective_enabled": True,
            "targets": {"endpoint_assessment_coverage": 1.0},
        },
    },
    "redteam": {
        "aliases": [],
        "completion_scope": "full_endpoint_assessment",
        "coverage_policy": {
            "endpoint_coverage_objective_enabled": True,
            "targets": {"endpoint_assessment_coverage": 1.0},
        },
    },
    "ctf-fast-score": {
        "aliases": [],
        "completion_scope": "challenge_path",
        "coverage_policy": {
            "endpoint_coverage_objective_enabled": False,
            "targets": {"endpoint_assessment_coverage": 0.0},
        },
    },
    "offense-high-value": {
        "aliases": [],
        "completion_scope": "high_value_paths",
        "coverage_policy": {
            "endpoint_coverage_objective_enabled": False,
            "targets": {"endpoint_assessment_coverage": 0.0},
        },
    },
    "daily-deliverable": {
        "aliases": [],
        "completion_scope": "prioritized_paths",
        "coverage_policy": {
            "endpoint_coverage_objective_enabled": False,
            "targets": {"endpoint_assessment_coverage": 0.0},
        },
    },
    "batch-asset-sweep": {
        "aliases": [],
        "completion_scope": "passive_triage",
        "coverage_policy": {
            "endpoint_coverage_objective_enabled": False,
            "targets": {"endpoint_assessment_coverage": 0.0},
        },
    },
    "cautious-waf-risk-control": {
        "aliases": [],
        "completion_scope": "low_risk_assessment",
        "coverage_policy": {
            "endpoint_coverage_objective_enabled": False,
            "targets": {"endpoint_assessment_coverage": 0.0},
        },
    },
}

# The user-facing order is intentionally stable.  In particular, reply "1" is the
# standard profile and never changes when the canonical registry is reordered.
PROFILE_SELECTION_ORDER: Tuple[str, ...] = (
    "standard-pentest",
    "redteam",
    "ctf-fast-score",
    "offense-high-value",
    "daily-deliverable",
    "batch-asset-sweep",
    "cautious-waf-risk-control",
)

_DESCRIPTIONS = {
    "ctf-fast-score": "CTF 快速得分",
    "redteam": "红队演练",
    "offense-high-value": "高价值 SRC/专项测试",
    "standard-pentest": "标准授权渗透",
    "daily-deliverable": "日常交付",
    "batch-asset-sweep": "批量资产被动分诊",
    "cautious-waf-risk-control": "谨慎 WAF/风险控制",
}

_EXTRA_ALIASES = {
    "ctf-fast-score": ("ctf", "flag"),
    "redteam": ("red team", "红队"),
    "offense-high-value": ("高价值", "src", "h1"),
    "standard-pentest": ("标准渗透", "标准"),
    "daily-deliverable": ("daily", "日报"),
    "batch-asset-sweep": ("批量", "资产分诊"),
    "cautious-waf-risk-control": ("谨慎", "风险控制"),
}

_URL_RE = re.compile(r"https?://[^\s\"'<>）)】\]]+", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?:/[^\s\"'<>）)】\]]*)?")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}"
    r"(?::\d{1,5})?(?:/[^\s\"'<>）)】\]]*)?",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class RequestDecision:
    """Deterministic result of parsing one inbound request."""

    target: Optional[str]
    instruction: str
    profile_name: Optional[str]
    requires_profile_choice: bool
    goal_exempt: bool
    profile_conflict: bool = False


def _load_registry_profiles(path: Path) -> Dict[str, Dict[str, Any]]:
    """Load the complete canonical profile map with the project's YAML loader."""
    if yaml is None or not path.is_file():
        return copy.deepcopy(_FALLBACK_REGISTRY_PROFILES)
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8-sig")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise RuntimeError(f"canonical operation profile registry unavailable: {path}") from exc
    profiles = document.get("profiles") if isinstance(document, dict) else None
    if not isinstance(profiles, dict) or not profiles:
        raise RuntimeError(f"canonical operation profile registry has no profiles: {path}")
    result: Dict[str, Dict[str, Any]] = {}
    for name, config in profiles.items():
        if not isinstance(name, str) or not isinstance(config, dict):
            raise RuntimeError("canonical operation profile registry has an invalid profile entry")
        aliases = config.get("aliases") or []
        if not isinstance(aliases, list) or not all(isinstance(alias, str) for alias in aliases):
            raise RuntimeError(f"canonical operation profile aliases are invalid: {name}")
        result[name] = copy.deepcopy(config)
    return result


_REGISTRY_PROFILES = _load_registry_profiles(_REGISTRY_PATH)
_registry_names = set(_REGISTRY_PROFILES)
if set(PROFILE_SELECTION_ORDER) != _registry_names:
    raise RuntimeError("profile selection order diverges from the canonical registry")


def _profile_config(name: str) -> Dict[str, object]:
    config = copy.deepcopy(_REGISTRY_PROFILES[name])
    aliases = list(config.get("aliases") or [])
    aliases.extend(_EXTRA_ALIASES.get(name, ()))
    aliases.extend((name, name.replace("-", "_")))
    config.update({
        "description": _DESCRIPTIONS[name],
        "aliases": tuple(dict.fromkeys(aliases)),
        "default_goal": name != "batch-asset-sweep",
        "stop_conditions": ("all_endpoints_audited", "timebox_2h", "rce_confirmed"),
        "auto_continue": name != "cautious-waf-risk-control",
        "broadcast_level": "summary",
    })
    return config


PROFILES: Dict[str, Dict[str, object]] = {
    name: _profile_config(name) for name in PROFILE_SELECTION_ORDER
}


def profile_names() -> Tuple[str, ...]:
    """Return the canonical profile names in stable choice order."""
    return PROFILE_SELECTION_ORDER


def get_profile(name: str) -> Optional[Dict[str, object]]:
    """Return an isolated runtime profile copy, or ``None`` for an unknown name."""
    profile = PROFILES.get(name)
    return copy.deepcopy(profile) if profile is not None else None


def list_profiles() -> Dict[str, Dict[str, object]]:
    """Return isolated copies so callers cannot mutate the runtime registry."""
    return copy.deepcopy(PROFILES)


def extract_target(text: str) -> Optional[str]:
    """Extract the first URL, IP, or domain target from an inbound command."""
    candidates = []
    for precedence, pattern in enumerate((_URL_RE, _IP_RE, _DOMAIN_RE)):
        match = pattern.search(text or "")
        if match:
            candidates.append((match.start(), precedence, match.group(0)))
    if not candidates:
        return None
    return min(candidates)[2].rstrip(".,;，。；）)】]")


def _text_without_targets(text: str) -> str:
    value = _URL_RE.sub(" ", text)
    value = _IP_RE.sub(" ", value)
    return _DOMAIN_RE.sub(" ", value)


def _contains_profile_token(text: str, token: str) -> bool:
    token = token.strip()
    if not token:
        return False
    if re.search(r"[a-z0-9]", token, re.IGNORECASE):
        return bool(
            re.search(
                rf"(?<![a-z0-9_-]){re.escape(token.lower())}(?![a-z0-9_-])",
                text.lower(),
            )
        )
    return token in text


def _explicit_profiles(text: str) -> Tuple[str, ...]:
    selection_text = _text_without_targets(text)
    matches = []
    for name in PROFILE_SELECTION_ORDER:
        aliases = PROFILES[name]["aliases"]
        if any(_contains_profile_token(selection_text, str(alias)) for alias in aliases):
            matches.append(name)
    return tuple(matches)


def _is_explicit_limited_analysis(text: str) -> bool:
    normalized = text.lower()
    explicit_limited = re.search(
        r"(?:只|仅|only)\s*(?:做)?\s*(?:限定|limited)\s*(?:分析|analy[sz]e)",
        normalized,
    )
    limited = re.search(r"(?:只|仅|only)\s*(?:做)?\s*(?:分析|analy[sz]e)", normalized)
    evidence_scope = re.search(
        r"\b(?:har|traffic|burp|request)\b|流量|请求包|限定分析|limited\s+analysis",
        normalized,
    )
    return bool(explicit_limited or (limited and evidence_scope))


def resolve_request(user_input: str) -> RequestDecision:
    """Resolve an inbound request without starting any task.

    Ordinary targets always enter profile selection.  A supplied canonical profile
    or alias is an explicit selection; a narrowly worded traffic-only request is
    intentionally recorded as a no-goal analysis request.
    """
    instruction = (user_input or "").strip()
    target = extract_target(instruction)
    goal_exempt = _is_explicit_limited_analysis(instruction)
    explicit_profiles = () if goal_exempt else _explicit_profiles(instruction)
    profile_conflict = len(explicit_profiles) > 1
    profile_name = explicit_profiles[0] if len(explicit_profiles) == 1 else None
    return RequestDecision(
        target=target,
        instruction=instruction,
        profile_name=profile_name,
        requires_profile_choice=bool(target and not goal_exempt and profile_name is None),
        goal_exempt=goal_exempt,
        profile_conflict=profile_conflict,
    )


def select_profile(user_input: str) -> Tuple[str, Dict[str, object]]:
    """Compatibility helper for older callers.

    New callers must use :func:`resolve_request`, which preserves the required
    profile-choice state instead of silently starting the standard profile.
    """
    decision = resolve_request(user_input)
    name = decision.profile_name or "standard-pentest"
    return name, get_profile(name) or {}


def prompt_strategy_selection(profile_ids: Optional[Iterable[str]] = None) -> str:
    """Build the short Chinese profile-choice prompt for CLI and Feishu callers."""
    names = tuple(profile_ids or PROFILE_SELECTION_ORDER)
    lines = ["请选择本次测试策略，回复编号："]
    for index, name in enumerate(names, 1):
        profile = PROFILES.get(name)
        if profile is None:
            continue
        lines.append(f"{index}. {name} - {profile['description']}")
    lines.append("明确只分析 HAR/流量时不创建 /goal。")
    return "\n".join(lines)


def _self_test() -> int:
    assert set(profile_names()) == set(_REGISTRY_PROFILES)
    assert resolve_request("/goal https://example.test").requires_profile_choice
    assert resolve_request("/goal ctf https://example.test").profile_name == "ctf-fast-score"
    assert resolve_request("只分析 https://example.test 的 HAR 流量").goal_exempt
    print("operation_profile self-test ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())
