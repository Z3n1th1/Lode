from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping
from urllib.parse import urlsplit


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _strings(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value.strip(),) if value.strip() else ()
    if isinstance(value, (list, tuple, set)):
        return tuple(str(item).strip() for item in value if str(item).strip())
    return ()


@dataclass(frozen=True)
class IntelQuery:
    """The immutable scope and authorization context for one collection run."""

    program: str
    authorization: str
    allowed_domains: tuple[str, ...] = ()
    allowed_hosts: tuple[str, ...] = ()
    allowed_ips: tuple[str, ...] = ()
    seed_urls: tuple[str, ...] = ()
    forbidden: tuple[str, ...] = ()
    forbidden_hosts: tuple[str, ...] = ()
    max_items: int = 200

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "IntelQuery":
        data: Mapping[str, Any] = value
        nested = value.get("scope")
        if isinstance(nested, Mapping):
            data = nested
        allowed_domains = _strings(data.get("allowed_domains"))
        allowed_hosts = _strings(data.get("allowed_hosts"))
        # A TargetCard normally has only allowed_hosts.  Keep that distinction
        # so confirming one host does not silently authorize every subdomain.
        if not allowed_domains and not allowed_hosts:
            allowed_hosts = _strings(data.get("hosts"))
        forbidden = _strings(data.get("forbidden"))
        forbidden_hosts = _strings(data.get("forbidden_hosts"))
        seed_urls = _strings(value.get("seed_urls")) or _strings(data.get("seed_urls")) or _strings(value.get("entrypoints"))
        authorization = str(value.get("authorization") or data.get("authorization") or "").strip()
        if not authorization and value.get("schema") == "TargetCard/v1":
            target_id = str(value.get("target_id") or "").strip()
            authorization = f"confirmed_target_card:{target_id}" if target_id else "confirmed_target_card"
        return cls(
            program=str(value.get("program") or value.get("name") or "authorized-program").strip(),
            authorization=authorization,
            allowed_domains=allowed_domains,
            allowed_hosts=allowed_hosts,
            allowed_ips=_strings(data.get("allowed_ips")),
            seed_urls=seed_urls,
            forbidden=forbidden,
            forbidden_hosts=forbidden_hosts,
            max_items=max(1, min(int(value.get("max_items", 200)), 10_000)),
        )

    def require_authorization(self) -> None:
        if not self.authorization.strip():
            raise ValueError("intel_authorization_required")
        if not self.allowed_domains and not self.allowed_hosts and not self.allowed_ips:
            raise ValueError("intel_scope_required")


@dataclass(frozen=True)
class AssetCandidate:
    value: str
    kind: str
    source: str
    observed_at: str = ""
    confidence: float = 0.5
    scope_status: str = "in_scope"
    evidence_ref: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)
    score: float = 0.0
    is_new: bool = False
    sources: tuple[str, ...] = field(default_factory=tuple)
    title: str = ""
    summary: str = ""
    published_at: str = ""

    @property
    def key(self) -> str:
        value = self.value.strip().rstrip("/").lower()
        if self.kind == "url":
            parsed = urlsplit(value)
            if parsed.hostname:
                # Fragments never identify a remotely observed asset.
                path = parsed.path or "/"
                try:
                    port = parsed.port
                except ValueError:
                    port = None
                return f"url:{parsed.scheme}://{parsed.hostname}{(':' + str(port)) if port else ''}{path}{('?' + parsed.query) if parsed.query else ''}"
        return f"{self.kind}:{value}"

    def with_updates(self, **changes: Any) -> "AssetCandidate":
        data = self.to_dict()
        data.update(changes)
        return AssetCandidate.from_mapping(data)

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "kind": self.kind,
            "source": self.source,
            "sources": list(self.sources or ((self.source,) if self.source else ())),
            "observed_at": self.observed_at or utc_now(),
            "confidence": round(max(0.0, min(float(self.confidence), 1.0)), 3),
            "scope_status": self.scope_status,
            "evidence_ref": self.evidence_ref,
            "tags": list(dict.fromkeys(self.tags)),
            "score": round(float(self.score), 2),
            "is_new": bool(self.is_new),
            "title": self.title,
            "summary": self.summary,
            "published_at": self.published_at,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "AssetCandidate":
        kind = str(value.get("kind") or "url").strip().lower()
        source = str(value.get("source") or "unknown").strip()[:100]
        sources = _strings(value.get("sources")) or ((source,) if source else ())
        return cls(
            value=str(value.get("value") or value.get("target") or value.get("url") or "").strip(),
            kind=kind,
            source=source,
            sources=sources,
            observed_at=str(value.get("observed_at") or "").strip(),
            confidence=float(value.get("confidence", 0.5) or 0.5),
            scope_status=str(value.get("scope_status") or "in_scope"),
            evidence_ref=str(value.get("evidence_ref") or "").strip()[:500],
            tags=_strings(value.get("tags")),
            score=float(value.get("score", 0.0) or 0.0),
            is_new=bool(value.get("is_new", False)),
            title=str(value.get("title") or "").strip()[:300],
            summary=str(value.get("summary") or "").strip()[:1000],
            published_at=str(value.get("published_at") or "").strip()[:80],
        )


@dataclass(frozen=True)
class ProviderStatus:
    provider: str
    status: str
    item_count: int = 0
    error: str = ""
    started_at: str = ""
    completed_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "status": self.status,
            "item_count": self.item_count,
            "error": self.error,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


@dataclass(frozen=True)
class RunReport:
    run_id: str
    program: str
    started_at: str
    completed_at: str
    candidates: tuple[AssetCandidate, ...]
    provider_status: tuple[ProviderStatus, ...]
    filtered_count: int = 0
    duplicate_count: int = 0
    previous_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "IntelRun/v1",
            "run_id": self.run_id,
            "program": self.program,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "counts": {
                "candidates": len(self.candidates),
                "filtered_out_of_scope": self.filtered_count,
                "duplicates_merged": self.duplicate_count,
                "previous_candidates": self.previous_count,
            },
            "providers": [item.to_dict() for item in self.provider_status],
            "candidates": [item.to_dict() for item in self.candidates],
        }


@dataclass(frozen=True)
class WatchSummary:
    status: str
    runs_completed: int
    last_run_id: str = ""
    consecutive_errors: int = 0
    last_error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "IntelWatchSummary/v1",
            "status": self.status,
            "runs_completed": self.runs_completed,
            "last_run_id": self.last_run_id,
            "consecutive_errors": self.consecutive_errors,
            "last_error": self.last_error,
        }
