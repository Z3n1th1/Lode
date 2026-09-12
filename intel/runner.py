from __future__ import annotations

import re
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Sequence
from urllib.parse import urlsplit

from .models import AssetCandidate, IntelQuery, ProviderStatus, RunReport, WatchSummary, utc_now
from .locking import FileLock
from .registry import load_sources, record_status
from .scope import IntelScope, PUBLIC_INTEL_KINDS
from .store import IntelStore
from .providers import CisaKevProvider, CrtShProvider, FeedProvider, FileProvider, IntelProvider, SeedProvider, TwitterProvider

_HIGH_VALUE = re.compile(r"(?:^|[./_-])(auth|login|signin|admin|dashboard|api|graphql|swagger|openapi|upload|export|payment|checkout|billing|oauth|sso)(?:$|[./?_-])", re.IGNORECASE)
_INTEL_HIGH_VALUE = re.compile(r"\b(?:CVE-\d{4}-\d+|PoC|0-?day|RCE|auth(?:entication|orization)? bypass|known exploited|in the wild)\b", re.IGNORECASE)


def _score(candidate: AssetCandidate, *, is_new: bool, source_count: int) -> float:
    score = candidate.confidence * 40.0
    haystack = f"{candidate.value} {candidate.title} {candidate.summary} {' '.join(candidate.tags)}"
    score += min(32.0, len(_HIGH_VALUE.findall(haystack)) * 8.0)
    if is_new:
        score += 25.0
    if source_count > 1:
        score += 15.0
    if "certificate-observed" in candidate.tags:
        score += 4.0
    if candidate.kind in PUBLIC_INTEL_KINDS:
        score += 15.0
        score += min(16.0, len(_INTEL_HIGH_VALUE.findall(haystack)) * 8.0)
    return min(100.0, score)


def _merge(current: AssetCandidate, incoming: AssetCandidate) -> AssetCandidate:
    sources = tuple(dict.fromkeys(current.sources + incoming.sources + (incoming.source,)))
    tags = tuple(dict.fromkeys(current.tags + incoming.tags))
    primary = current if current.confidence >= incoming.confidence else incoming
    return AssetCandidate(
        value=primary.value,
        kind=primary.kind,
        source=primary.source,
        sources=sources,
        observed_at=max(current.observed_at or "", incoming.observed_at or ""),
        confidence=max(current.confidence, incoming.confidence),
        scope_status="in_scope",
        evidence_ref=primary.evidence_ref or current.evidence_ref or incoming.evidence_ref,
        tags=tags,
        title=primary.title or current.title or incoming.title,
        summary=primary.summary or current.summary or incoming.summary,
        published_at=primary.published_at or current.published_at or incoming.published_at,
    )


def collect(
    query: IntelQuery,
    providers: Sequence[IntelProvider],
    *,
    timeout: float = 8.0,
    max_items: int | None = None,
    store: IntelStore | None = None,
    run_id: str | None = None,
    registry_path: str | Path | None = None,
) -> RunReport:
    """Run passive providers, then enforce scope before persistence and ranking."""
    query.require_authorization()
    started_at = utc_now()
    scope = IntelScope(query)
    previous = store.previous_keys() if store else set()
    merged: dict[str, AssetCandidate] = {}
    statuses: list[ProviderStatus] = []
    filtered_count = 0
    duplicate_count = 0
    item_limit = max(1, min(max_items or query.max_items, 10_000))

    for provider in providers:
        provider_started = utc_now()
        try:
            raw_items = provider.collect(query, timeout=timeout, max_items=item_limit)
            accepted = 0
            for raw in raw_items:
                candidate = raw if isinstance(raw, AssetCandidate) else AssetCandidate.from_mapping(raw)
                if not candidate.value:
                    continue
                decision = scope.check_candidate(candidate)
                if not decision.allowed:
                    filtered_count += 1
                    continue
                candidate = candidate.with_updates(scope_status="in_scope", observed_at=candidate.observed_at or utc_now())
                key = candidate.key
                if key in merged:
                    merged[key] = _merge(merged[key], candidate)
                    duplicate_count += 1
                else:
                    merged[key] = candidate
                    accepted += 1
                if len(merged) >= item_limit:
                    break
            statuses.append(ProviderStatus(provider=provider.id, status="ok", item_count=accepted, started_at=provider_started, completed_at=utc_now()))
        except Exception as exc:  # provider failure is isolated and visible in the report
            statuses.append(ProviderStatus(provider=provider.id, status="error", error=f"{exc.__class__.__name__}: {exc}", started_at=provider_started, completed_at=utc_now()))

    candidates: list[AssetCandidate] = []
    for candidate in merged.values():
        is_new = candidate.key not in previous
        candidate = candidate.with_updates(
            is_new=is_new,
            score=_score(candidate, is_new=is_new, source_count=len(candidate.sources or (candidate.source,))),
        )
        candidates.append(candidate)
    candidates.sort(key=lambda item: (-item.score, item.kind, item.value))
    candidates = candidates[:item_limit]
    report = RunReport(
        run_id=run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8],
        program=query.program,
        started_at=started_at,
        completed_at=utc_now(),
        candidates=tuple(candidates),
        provider_status=tuple(statuses),
        filtered_count=filtered_count,
        duplicate_count=duplicate_count,
        previous_count=len(previous),
    )
    if store:
        store.write(report)
    if registry_path is not None:
        for status in report.provider_status:
            record_status(status.provider, status.status, item_count=status.item_count, error=status.error, value=registry_path)
    return report


def run_watch(
    query: IntelQuery,
    provider_source: Sequence[IntelProvider] | Callable[[], Sequence[IntelProvider]],
    *,
    store: IntelStore,
    interval_sec: float = 900.0,
    timeout: float = 8.0,
    max_items: int | None = None,
    max_runs: int = 0,
    max_consecutive_errors: int = 5,
    stop_event: threading.Event | None = None,
    sleep_fn: Callable[[float], None] | None = None,
    registry_path: str | Path | None = None,
    on_report: Callable[[RunReport], None] | None = None,
) -> WatchSummary:
    """Run repeated passive collection with one process owning the watch lock.

    ``max_runs=0`` means unlimited. A run counts as failed only when every
    configured provider returns an error; one broken feed therefore cannot stop
    healthy sources. The watch never invokes active scanners or LLM tools.
    """
    query.require_authorization()
    IntelScope(query)
    interval_sec = float(interval_sec)
    if interval_sec < 1.0:
        raise ValueError("intel_watch_interval_too_short")
    if max_runs < 0:
        raise ValueError("intel_watch_max_runs_invalid")
    max_consecutive_errors = max(1, int(max_consecutive_errors))
    event = stop_event or threading.Event()
    started_at = utc_now()
    runs_completed = 0
    consecutive_errors = 0
    last_run_id = ""
    last_error = ""
    final_status = "stopped"

    with FileLock(store.watch_lock_path, timeout_seconds=0.1):
        previous_state = store.read_watch_state()
        recovered_previous = previous_state.get("status") == "running"
        if recovered_previous:
            store.write_watch_state({
                **previous_state,
                "status": "recovered",
                "recovered_at": utc_now(),
                "last_error": "watch_restarted_after_interruption",
            })
        store.write_watch_state({
            "schema": "IntelWatchState/v1",
            "status": "running",
            "program": query.program,
            "started_at": started_at,
            "runs_completed": 0,
            "last_run_id": "",
            "consecutive_errors": 0,
            "last_error": "",
            "recovered_previous": recovered_previous,
            "interval_sec": interval_sec,
            "max_runs": max_runs,
        })
        try:
            while not event.is_set() and (max_runs == 0 or runs_completed < max_runs):
                report: RunReport | None = None
                try:
                    providers = provider_source() if callable(provider_source) else provider_source
                    report = collect(
                        query,
                        list(providers),
                        timeout=timeout,
                        max_items=max_items,
                        store=store,
                        registry_path=registry_path,
                    )
                    runs_completed += 1
                    last_run_id = report.run_id
                    errors = [item.error for item in report.provider_status if item.status == "error" and item.error]
                    if report.provider_status and len(errors) < len(report.provider_status):
                        consecutive_errors = 0
                        last_error = ""
                    else:
                        consecutive_errors += 1
                        last_error = "; ".join(errors[:3]) or "no_provider_succeeded"
                    if on_report is not None:
                        on_report(report)
                except Exception as exc:  # state/collection failure is persisted before retry or stop
                    runs_completed += 1
                    consecutive_errors += 1
                    last_error = f"{exc.__class__.__name__}: {exc}"[:500]
                store.write_watch_state({
                    "schema": "IntelWatchState/v1",
                    "status": "running",
                    "program": query.program,
                    "started_at": started_at,
                    "last_run_at": utc_now(),
                    "runs_completed": runs_completed,
                    "last_run_id": last_run_id,
                    "consecutive_errors": consecutive_errors,
                    "last_error": last_error,
                    "recovered_previous": recovered_previous,
                    "interval_sec": interval_sec,
                    "max_runs": max_runs,
                })
                if consecutive_errors >= max_consecutive_errors:
                    final_status = "failed"
                    break
                if max_runs and runs_completed >= max_runs:
                    final_status = "completed"
                    break
                if sleep_fn is not None:
                    sleep_fn(interval_sec)
                elif event.wait(interval_sec):
                    break
            if event.is_set() and final_status != "failed":
                final_status = "stopped"
            elif max_runs and runs_completed >= max_runs and final_status != "failed":
                final_status = "completed"
        finally:
            store.write_watch_state({
                "schema": "IntelWatchState/v1",
                "status": final_status,
                "program": query.program,
                "started_at": started_at,
                "stopped_at": utc_now(),
                "runs_completed": runs_completed,
                "last_run_id": last_run_id,
                "consecutive_errors": consecutive_errors,
                "last_error": last_error,
                "recovered_previous": recovered_previous,
                "interval_sec": interval_sec,
                "max_runs": max_runs,
            })

    return WatchSummary(
        status=final_status,
        runs_completed=runs_completed,
        last_run_id=last_run_id,
        consecutive_errors=consecutive_errors,
        last_error=last_error,
    )


def providers_from_registry(value: str | Path | None = None, *, file_paths: Iterable[str | Path] = ()) -> list[IntelProvider]:
    providers: list[IntelProvider] = []
    for source in load_sources(value):
        if source.get("enabled") is not True:
            continue
        provider = str(source.get("provider") or source.get("kind") or "").strip().lower()
        if provider == "seed":
            providers.append(SeedProvider(str(source.get("id") or "seed")))
        elif provider == "crtsh":
            providers.append(CrtShProvider(source_id=str(source.get("id") or "crtsh")))
        elif provider == "cisa_kev":
            providers.append(CisaKevProvider(str(source.get("id") or "builtin-cisa-kev"), url=str(source.get("url") or "")))
        elif provider in {"rss", "page_watch"} and source.get("url"):
            providers.append(FeedProvider(str(source.get("id")), str(source["url"]), kind=provider, tags=tuple(source.get("tags") or ())))
        elif provider == "twitter":
            watch = source.get("watch") if isinstance(source.get("watch"), dict) else {}
            providers.append(TwitterProvider(
                str(source.get("id") or "twitter"),
                str(source.get("query") or watch.get("query") or ""),
                api_url=str(source.get("url") or "https://api.x.com/2/tweets/search/recent"),
            ))
    for path in file_paths:
        providers.append(FileProvider(path))
    # A missing registry still needs a useful deterministic default.
    if not providers:
        providers = [SeedProvider(), CrtShProvider()]
    return providers
