from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .locking import FileLock
from .network import UnsafeSourceUrl, validate_source_url

MAX_SOURCES = 100
BUILTIN_SOURCES: tuple[dict[str, Any], ...] = (
    {
        "id": "builtin-seed",
        "provider": "seed",
        "kind": "builtin",
        "name": "授权范围 seed",
        "url": "",
        "enabled": True,
        "trusted": True,
        "tags": ["passive", "scope"],
    },
    {
        "id": "builtin-crtsh",
        "provider": "crtsh",
        "kind": "builtin",
        "name": "crt.sh 证书透明度",
        "url": "https://crt.sh/",
        "enabled": True,
        "trusted": True,
        "tags": ["passive", "certificate", "subdomain"],
    },
    {
        "id": "builtin-cisa-kev",
        "provider": "cisa_kev",
        "kind": "builtin",
        "name": "CISA Known Exploited Vulnerabilities",
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "enabled": True,
        "trusted": True,
        "tags": ["public-intel", "cve", "known-exploited"],
    },
)


def source_path(value: str | Path | None) -> Path:
    path = Path(value) if value else Path(os.environ.get("PA_INTEL_SOURCES_PATH", "intel-sources.json"))
    if path.suffix.lower() != ".json":
        path = path / "sources.json"
    return path


def _read(path: Path) -> list[dict[str, Any]]:
    if path.is_symlink() or not path.is_file():
        return [dict(item) for item in BUILTIN_SOURCES]
    try:
        decoded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return [dict(item) for item in BUILTIN_SOURCES]
    values = decoded.get("sources") if isinstance(decoded, dict) else decoded
    if not isinstance(values, list):
        return [dict(item) for item in BUILTIN_SOURCES]
    result = [dict(item) for item in BUILTIN_SOURCES]
    for item in values:
        if not isinstance(item, Mapping) or not item.get("id"):
            continue
        if str(item["id"]) in {str(b["id"]) for b in result}:
            result = [existing for existing in result if existing.get("id") != item["id"]]
        result.append(dict(item))
    return result[:MAX_SOURCES]


def _write(path: Path, sources: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({"schema": "IntelSources/v1", "sources": sources}, ensure_ascii=False, indent=2, sort_keys=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.stem}-", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def _valid_user_url(value: str) -> tuple[bool, str]:
    try:
        # Do not resolve at configuration time: offline deployments often add
        # feeds before DNS is available.  The network fetch resolves again.
        normalized = validate_source_url(value, resolve=False)
    except (UnsafeSourceUrl, ValueError) as exc:
        return False, str(exc)
    return True, normalized


def load_sources(value: str | Path | None = None) -> list[dict[str, Any]]:
    return _read(source_path(value))


def add_source(payload: Mapping[str, Any], value: str | Path | None = None) -> tuple[bool, str]:
    kind = str(payload.get("kind") or "").strip().lower()
    if kind not in {"rss", "page_watch", "twitter"}:
        return False, "source_kind_not_allowed"
    name = str(payload.get("name") or kind).strip()[:80]
    url = str(payload.get("url") or "").strip()
    if not name:
        return False, "source_name_required"
    query = str(payload.get("query") or "").strip()[:256]
    if kind == "twitter" and not url:
        url = "https://api.x.com/2/tweets/search/recent"
    if kind == "twitter" and not query:
        return False, "twitter_query_required"
    ok, normalized_or_error = _valid_user_url(url)
    if not ok:
        return False, normalized_or_error
    interval = payload.get("interval_sec", 1800)
    try:
        interval = max(300, min(int(interval), 86_400))
    except (TypeError, ValueError):
        return False, "source_interval_invalid"
    identity = f"{kind}\0{normalized_or_error}\0{query if kind == 'twitter' else ''}"
    source_id = "user-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]
    path = source_path(value)
    with FileLock(path.with_suffix(path.suffix + ".lock")):
        sources = load_sources(value)
        if any(item.get("id") == source_id for item in sources):
            return False, "source_already_exists"
        sources.append({
            "id": source_id,
            "provider": kind,
            "kind": kind,
            "name": name,
            "url": normalized_or_error,
            "enabled": kind != "twitter",
            "trusted": False,
            "interval_sec": interval,
            "watch": dict(payload.get("watch") or {}),
            "query": query,
            "tags": ["user-configured", "untrusted"] + (["credentialed", "social"] if kind == "twitter" else []),
        })
        try:
            _write(path, sources[:MAX_SOURCES])
        except OSError as exc:
            return False, f"source_write_failed:{exc.__class__.__name__}"
    return True, source_id


def set_enabled(source_id: str, enabled: bool, value: str | Path | None = None) -> bool:
    path = source_path(value)
    with FileLock(path.with_suffix(path.suffix + ".lock")):
        sources = load_sources(value)
        found = False
        for item in sources:
            if item.get("id") == source_id:
                item["enabled"] = bool(enabled)
                found = True
                break
        if found:
            _write(path, sources)
        return found


def remove_source(source_id: str, value: str | Path | None = None) -> bool:
    if str(source_id).startswith("builtin-"):
        return False
    path = source_path(value)
    with FileLock(path.with_suffix(path.suffix + ".lock")):
        sources = load_sources(value)
        kept = [item for item in sources if item.get("id") != source_id]
        if len(kept) == len(sources):
            return False
        _write(path, kept)
        return True


def record_status(source_id: str, status: str, *, item_count: int = 0, error: str = "", value: str | Path | None = None) -> bool:
    """Persist bounded run metadata so untested/broken sources are visible."""
    path = source_path(value)
    with FileLock(path.with_suffix(path.suffix + ".lock")):
        sources = load_sources(value)
        aliases = {"seed": "builtin-seed", "crtsh": "builtin-crtsh", "cisa-kev": "builtin-cisa-kev"}
        if not any(item.get("id") == source_id for item in sources):
            source_id = aliases.get(source_id, source_id)
        for item in sources:
            if item.get("id") != source_id:
                continue
            item["last_run"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            item["last_status"] = str(status)[:24]
            item["last_error"] = str(error)[:300]
            item["item_count"] = max(0, min(int(item_count), 100_000))
            _write(path, sources)
            return True
    return False
