"""Local LLM provider settings for Lode.

Stores the operator's own provider list (``name | base_url | api_key | model``)
plus the reasoner/explorer tier selection in a local JSON file, and projects
them into the environment variables that :mod:`core.llm_pool` (and
:mod:`core.llm_client`) understand — so the Console can configure models
without editing ``.env``.

Credential discipline: keys exist only in this local file (under the
git-ignored ``lode-state/`` directory) and in process memory. They are never
logged and never returned by the API; reads go through :func:`mask_settings`.

Precedence: a real environment variable (including one injected from ``.env``)
always wins over the saved file, matching :func:`core.config.load_dotenv`.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

SCHEMA = "LlmSettings/v1"
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_PROVIDERS = 12
DEFAULT_BASE_URL = "https://api.deepseek.com"
DEFAULT_MODEL = "deepseek-chat"
TIER_ROLES = ("reasoner", "explorer")

# 这些 env var 由本模块负责投影(供 core.llm_pool / core.llm_client / agents 消费)。
PROVIDERS_ENV = "LLM_PROVIDERS"
LEGACY_KEYS = ("LLM_API_KEY", "LLM_BASE_URL", "LLM_MODEL")
PREFER_ENV = {"reasoner": "SRC_REASONER_PREFER", "explorer": "SRC_EXPLORER_PREFER"}
ACTIVE_FILE_ENV = "LLM_ACTIVE_PROVIDER_FILE"

_NAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
# name|base_url|api_key|model 以 , 和 | 分隔 —— 字段里带分隔符会被解析器静默吞掉。
_DELIMITERS = (",", "|", "\n", "\r")


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def settings_path(state_dir: Optional[str | Path] = None) -> Path:
    """Location of the settings file (``LODE_LLM_SETTINGS_FILE`` wins)."""
    override = os.environ.get("LODE_LLM_SETTINGS_FILE", "").strip()
    if override:
        return Path(override)
    base = str(state_dir).strip() if state_dir else os.environ.get("LODE_STATE_DIR", "").strip()
    return Path(base) / "llm_settings.json" if base else _project_root() / "lode-state" / "llm_settings.json"


def _text(value: Any, limit: int = 200) -> str:
    return str(value or "").strip()[:limit]


def _empty() -> Dict[str, Any]:
    return {"schema": SCHEMA, "updated_at": 0.0, "providers": [], "tiers": {"reasoner": "", "explorer": ""}}


def _has_delimiter(value: str) -> bool:
    return any(ch in value for ch in _DELIMITERS)


def normalize_providers(
    providers: Any,
    *,
    stored: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Validate/normalize an incoming provider list.

    Returns ``{"providers": [...], "errors": [...]}``. Providers that already
    have a stored key keep it when the request arrives with an empty
    ``api_key`` (the API never returns keys, so a round-tripped form is blank);
    ``clear_key=True`` opts out of that carry-over.
    """
    if not isinstance(providers, Sequence) or isinstance(providers, (str, bytes)):
        return {"providers": [], "errors": ["providers_must_be_list"]}
    stored_by_name = {
        str(p.get("name")): p
        for p in ((stored or {}).get("providers") or [])
        if isinstance(p, Mapping) and p.get("name")
    }
    out: List[Dict[str, str]] = []
    errors: List[str] = []
    seen: set[str] = set()
    raw_list = list(providers)
    if len(raw_list) > MAX_PROVIDERS:
        errors.append("too_many_providers")
    for raw in raw_list[:MAX_PROVIDERS]:
        if not isinstance(raw, Mapping):
            errors.append("provider_not_object")
            continue
        name = _text(raw.get("name"), 64)
        base = _text(raw.get("base_url"), 300).rstrip("/") or DEFAULT_BASE_URL
        model = _text(raw.get("model"), 120) or DEFAULT_MODEL
        key = str(raw.get("api_key") or "").strip()
        clear = bool(raw.get("clear_key"))
        if not _NAME_RE.fullmatch(name):
            errors.append(f"invalid_provider_name:{name[:32] or '?'}")
            continue
        if name in seen:
            errors.append(f"duplicate_provider_name:{name}")
            continue
        if not (base.startswith("http://") or base.startswith("https://")):
            errors.append(f"invalid_base_url:{name}")
            continue
        if _has_delimiter(name) or _has_delimiter(base) or _has_delimiter(model) or _has_delimiter(key):
            errors.append(f"field_contains_delimiter:{name}")
            continue
        seen.add(name)
        if not key:
            keep = stored_by_name.get(name)
            if keep and not clear:
                key = str(keep.get("api_key") or "").strip()
        out.append({"name": name, "base_url": base, "api_key": key, "model": model})
    return {"providers": out, "errors": errors}


def normalize_tiers(tiers: Any) -> Dict[str, str]:
    """Normalize the reasoner/explorer selection (empty = let the pool fail over)."""
    source = tiers if isinstance(tiers, Mapping) else {}
    out: Dict[str, str] = {}
    for role in TIER_ROLES:
        value = _text(source.get(role), 64)
        out[role] = "" if _has_delimiter(value) else value
    return out


def read_settings(path: Optional[str | Path] = None) -> Dict[str, Any]:
    """Tolerant read; a missing/corrupt/unreadable file yields empty settings."""
    target = Path(path) if path else settings_path()
    try:
        if not target.is_file() or target.is_symlink():
            return _empty()
        if target.stat().st_size > MAX_FILE_BYTES:
            return _empty()
        doc = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return _empty()
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        return _empty()
    normalized = normalize_providers(doc.get("providers") or [])
    return {
        "schema": SCHEMA,
        "updated_at": float(doc.get("updated_at") or 0.0),
        "providers": normalized["providers"],
        "tiers": normalize_tiers(doc.get("tiers")),
    }


def write_settings(
    providers: Any,
    tiers: Any = None,
    *,
    path: Optional[str | Path] = None,
    stored: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Validate and atomically persist the settings. Returns the stored doc."""
    normalized = normalize_providers(providers, stored=stored)
    if normalized["errors"]:
        raise ValueError(";".join(normalized["errors"]))
    doc = {
        "schema": SCHEMA,
        "updated_at": time.time(),
        "providers": normalized["providers"],
        "tiers": normalize_tiers(tiers),
    }
    target = Path(path) if path else settings_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    staged = target.with_name("." + target.name + ".tmp")
    staged.write_text(json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(staged, target)
    return doc


def mask_settings(doc: Mapping[str, Any]) -> Dict[str, Any]:
    """Render settings for the API: never includes an ``api_key``."""
    return {
        "schema": SCHEMA,
        "updated_at": float(doc.get("updated_at") or 0.0),
        "tiers": dict(doc.get("tiers") or {}),
        "providers": [
            {
                "name": _text(p.get("name"), 64),
                "base_url": _text(p.get("base_url"), 300),
                "model": _text(p.get("model"), 120),
                "key_set": bool(str(p.get("api_key") or "").strip()),
                "key_hint": str(p.get("api_key") or "").strip()[-4:],
            }
            for p in (doc.get("providers") or [])
            if isinstance(p, Mapping)
        ],
    }


def build_providers_env(doc: Mapping[str, Any]) -> str:
    """Serialize to the ``LLM_PROVIDERS`` format (keyless providers dropped)."""
    groups = [
        "{}|{}|{}|{}".format(p["name"], p["base_url"], p["api_key"], p["model"])
        for p in (doc.get("providers") or [])
        if isinstance(p, Mapping) and str(p.get("api_key") or "").strip()
    ]
    return ",".join(groups)


def default_provider(doc: Mapping[str, Any]) -> Optional[Dict[str, str]]:
    """The provider the legacy single-key env trio should point at."""
    providers = [p for p in (doc.get("providers") or []) if isinstance(p, Mapping) and str(p.get("api_key") or "").strip()]
    if not providers:
        return None
    wanted = str((doc.get("tiers") or {}).get("reasoner") or "").strip().lower()
    if wanted:
        match = next(((p for p in providers if wanted in (str(p.get("name")) + str(p.get("model"))).lower())), None)
        if match:
            return dict(match)
    return dict(providers[0])


def apply_to_environ(
    doc: Mapping[str, Any],
    *,
    state_dir: Optional[str | Path] = None,
    force: bool = False,
) -> List[str]:
    """Project settings into the env vars the agent/model client read.

    Without ``force`` only missing or blank variables are filled, so a real
    environment variable (or one injected from ``.env``) keeps winning.
    """
    values: Dict[str, str] = {}
    providers_env = build_providers_env(doc)
    if providers_env:
        values[PROVIDERS_ENV] = providers_env
    chosen = default_provider(doc)
    if chosen:
        values["LLM_API_KEY"] = chosen.get("api_key", "")
        values["LLM_BASE_URL"] = chosen.get("base_url", "")
        values["LLM_MODEL"] = chosen.get("model", "")
    tiers = doc.get("tiers") or {}
    for role, env_name in PREFER_ENV.items():
        value = str(tiers.get(role) or "").strip()
        if value:
            values[env_name] = value
    if state_dir and not os.environ.get(ACTIVE_FILE_ENV, "").strip():
        # 让 header 的"切换当前模型"与应用内的 provider 池指向同一个文件。
        values[ACTIVE_FILE_ENV] = str(Path(state_dir) / "model_active_provider.json")

    applied: List[str] = []
    for key, value in values.items():
        if not value:
            continue
        if not force and os.environ.get(key, "").strip():
            continue
        if os.environ.get(key) == value:
            continue
        os.environ[key] = value
        applied.append(key)
    return applied


def load_llm_settings(
    path: Optional[str | Path] = None,
    *,
    state_dir: Optional[str | Path] = None,
    force: bool = False,
) -> int:
    """Read saved settings and merge into the environment. Never raises."""
    try:
        doc = read_settings(path if path is not None else settings_path(state_dir))
        return len(apply_to_environ(doc, state_dir=state_dir, force=force))
    except Exception:  # noqa: BLE001 - settings are advisory at startup
        return 0


__all__ = [
    "SCHEMA",
    "PROVIDERS_ENV",
    "LEGACY_KEYS",
    "ACTIVE_FILE_ENV",
    "settings_path",
    "normalize_providers",
    "normalize_tiers",
    "read_settings",
    "write_settings",
    "mask_settings",
    "build_providers_env",
    "default_provider",
    "apply_to_environ",
    "load_llm_settings",
]
