"""SignalHarbor: bounded public RSS -> AI summary -> one-way notifications."""
from __future__ import annotations

import hashlib
import json
import os
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from core.confidentiality import sanitize_external_text
from intel.locking import FileLock
from intel.network import fetch_url, validate_source_url
from intel.providers.feed import _feed_entries
from intel.store import _atomic_json
from .summarizer import _deepseek_summary, credential_post

MAX_SOURCES = 20
MAX_CACHE = 1000
MAX_FEED_BYTES = 2_000_000


class _FeedTreeBuilder(ET.TreeBuilder):
    def doctype(self, name: str, pubid: str, system: str) -> None:
        raise ValueError("rss_dtd_or_entity_rejected")


def _parse_feed_root(raw: bytes) -> ET.Element:
    """Parse bounded RSS/Atom input and reject DTD/entity declarations."""
    if len(raw) > MAX_FEED_BYTES:
        raise ValueError("rss_response_too_large")
    # DTDs and entity declarations are unnecessary for public feeds and can
    # trigger parser expansion/resource exhaustion. CDATA is valid RSS and
    # must remain accepted.
    document = raw.lower()
    if b"<!doctype" in document or b"<!entity" in document or b"<![entity" in document:
        raise ValueError("rss_dtd_or_entity_rejected")
    try:
        return ET.fromstring(raw, parser=ET.XMLParser(target=_FeedTreeBuilder()))
    except ET.ParseError as exc:
        raise ValueError("rss_xml_invalid") from exc


def _read_json(path: Path, limit: int) -> dict[str, Any]:
    if path.is_symlink():
        raise ValueError("news_symlink_rejected")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("news_state_too_large")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("news_json_object_required")
    return value


def load_sources(path: Path) -> list[dict[str, str]]:
    doc = _read_json(path, 256 * 1024)
    rows = doc.get("sources")
    if doc.get("schema") != "IntelSources/v1" or not isinstance(rows, list):
        raise ValueError("news_registry_invalid")
    enabled = [row for row in rows if isinstance(row, dict) and row.get("enabled") is True]
    if not 1 <= len(enabled) <= MAX_SOURCES:
        raise ValueError("news_requires_1_to_20_sources")
    result = []
    for row in enabled:
        if row.get("provider", row.get("kind")) not in {"rss", "atom"}:
            raise ValueError("news_only_rss_atom_allowed")
        url = validate_source_url(str(row.get("url", "")), resolve=False)
        result.append({"url": url, "name": str(row.get("name") or row.get("id") or "RSS")[:100]})
    return result


def _webhook() -> str:
    value = os.environ.get("FEISHU_WEBHOOK", "").strip()
    url = urlsplit(value)
    if (url.scheme != "https" or url.netloc != "open.feishu.cn"
            or not url.path.startswith("/open-apis/bot/v2/hook/")
            or not url.path.split("/")[-1] or url.query or url.fragment):
        raise ValueError("official_feishu_webhook_required")
    return value


def send_article(row: dict[str, Any]) -> bool:
    from notify.feishu_notifier import NotifyEvent, build_payload
    payload = build_payload(NotifyEvent(
        level="P2", title="SignalHarbor | " + row["title"][:160],
        body=f"{row['ai_summary'][:300]}\n{row['source']}\n{row['url']}",
    ), os.environ.get("FEISHU_SECRET", ""))
    response = credential_post(_webhook(), payload, timeout=10)
    return (type(response.get("code")) is int and response["code"] == 0
            or type(response.get("StatusCode")) is int and response["StatusCode"] == 0)


def run_cycle(registry: Path, state_dir: Path, *, no_ai: bool = False, feishu: bool = False,
              allow_missing_ai: bool = False,
              max_ai_items: int = 5, max_messages: int = 3, timeout: float = 8,
              fetcher: Callable = fetch_url, summarizer: Callable = _deepseek_summary,
              sender: Callable = send_article) -> dict[str, Any]:
    if not 1 <= max_ai_items <= 20 or not 1 <= max_messages <= 10 or not 1 <= timeout <= 30:
        raise ValueError("news_limits_invalid")
    sources = load_sources(registry)
    ai_skipped = False
    if not no_ai and summarizer is _deepseek_summary and not os.environ.get("DEEPSEEK_API_KEY", "").strip():
        if allow_missing_ai:
            no_ai = True
            ai_skipped = True
        else:
            raise ValueError("DEEPSEEK_API_KEY_required_or_use_no_ai")
    if feishu and sender is send_article:
        _webhook()
    if state_dir.is_symlink():
        raise ValueError("news_symlink_rejected")
    state_dir.mkdir(parents=True, exist_ok=True)
    state_path = state_dir / "news-state.json"
    if state_path.is_symlink() or (state_dir / "last-run.json").is_symlink():
        raise ValueError("news_symlink_rejected")
    if (state_dir / "cycle.lock").is_symlink():
        raise ValueError("news_symlink_rejected")
    with FileLock(state_dir / "cycle.lock", timeout_seconds=0.1):
        state = _read_json(state_path, 8 * 1024 * 1024) if state_path.exists() else {}
        cache = state.get("articles", {})
        if not isinstance(cache, dict) or any(not isinstance(row, dict) for row in cache.values()):
            raise ValueError("news_cache_invalid")
        statuses = []
        for source in sources:
            try:
                raw = fetcher(source["url"], timeout=timeout, max_bytes=MAX_FEED_BYTES)
                # A login/WAF HTML page must not be mistaken for a news feed.
                if _parse_feed_root(raw).tag.rsplit("}", 1)[-1].lower() not in {"rss", "feed", "rdf"}:
                    raise ValueError("rss_or_atom_required")
                entries = _feed_entries(raw, source["url"])[:20]
                for entry in entries:
                    if not entry.title:
                        continue
                    try:
                        url = validate_source_url(entry.url, resolve=False)
                    except ValueError:
                        continue
                    if len(url) > 300:
                        continue
                    identity = hashlib.sha256(url.encode("utf-8")).hexdigest()
                    if identity not in cache:
                        cache[identity] = {
                            "url": url, "source": source["name"], "title": sanitize_external_text(entry.title, limit=240),
                            "summary": sanitize_external_text(entry.summary, limit=600),
                            "published_at": entry.published_at, "seen_at": time.time(), "ai_summary": "", "delivered": False,
                        }
                statuses.append({"source": source["name"], "status": "ok", "items": len(entries)})
            except Exception as exc:
                statuses.append({"source": source["name"], "status": "error", "error": type(exc).__name__})
        pending = [row for row in cache.values()
                   if not row.get("ai_summary") or (not no_ai and row.get("summary_mode") == "source")]
        ai_errors = 0
        for row in pending[:max_ai_items]:
            try:
                summary = (row["summary"] or row["title"]) if no_ai else summarizer(row["title"], row["summary"])
                row["ai_summary"] = sanitize_external_text(summary, limit=500)
                if not row["ai_summary"]:
                    raise ValueError("empty_ai_summary")
                row["summary_mode"] = "source" if no_ai else "deepseek"
                row.pop("ai_error", None)
            except Exception as exc:
                ai_errors += 1
                row["ai_error"] = type(exc).__name__
        # Rolling cache bounds disk use; no growing per-run artifacts.
        cache = dict(sorted(cache.items(), key=lambda pair: pair[1].get("seen_at", 0))[-MAX_CACHE:])
        state = {"schema": "SignalHarborState/v1", "articles": cache}
        _atomic_json(state_path, state)
        sent = 0
        delivery_errors = 0
        if feishu:
            outbox = [row for row in cache.values() if row.get("ai_summary") and not row.get("delivered")]
            for row in outbox[:max_messages]:
                try:
                    if not sender(row):
                        raise ValueError("feishu_message_rejected")
                    row["delivered"] = True
                    sent += 1
                    _atomic_json(state_path, state)
                except Exception:
                    delivery_errors += 1
        result = {
            "schema": "SignalHarborRun/v1", "completed_at": time.time(), "providers": statuses,
            "cached": len(cache), "summary_attempts": min(len(pending), max_ai_items),
            "summary_errors": ai_errors, "sent": sent, "delivery_errors": delivery_errors,
            # A failed summary is isolated to its article; collection remains a
            # successful cycle and can retry the item on the next timer tick.
            "ok": any(row["status"] == "ok" for row in statuses) and not delivery_errors,
            "degraded": bool(ai_errors or delivery_errors or ai_skipped
                              or any(row["status"] != "ok" for row in statuses)),
            "ai_skipped": ai_skipped,
        }
        _atomic_json(state_dir / "last-run.json", result)
        return result
