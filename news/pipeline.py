"""Pulse: bounded public RSS -> AI summary -> one-way notifications."""
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
from .channels import discord_webhook, send_discord_article
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
        level="P2", title="Pulse | " + row["title"][:160],
        body=f"{row['ai_summary'][:300]}\n{row['source']}\n{row['url']}",
    ), os.environ.get("FEISHU_SECRET", ""))
    response = credential_post(_webhook(), payload, timeout=10)
    return (type(response.get("code")) is int and response["code"] == 0
            or type(response.get("StatusCode")) is int and response["StatusCode"] == 0)


def _pending_delivery(row: dict[str, Any], enabled: set[str]) -> bool:
    delivered = row.get("delivered_channels", {})
    targets = enabled | set(row.get("delivery_targets", []))
    return bool(row.get("delivery_error")) or any(not delivered.get(name) for name in targets)


def run_cycle(registry: Path, state_dir: Path, *, no_ai: bool = False, feishu: bool = False,
              discord: bool = False, dry_run: bool = False,
              allow_missing_ai: bool = False,
              max_ai_items: int = 5, max_messages: int = 3, timeout: float = 8,
              fetcher: Callable = fetch_url, summarizer: Callable = _deepseek_summary,
              sender: Callable = send_article,
              discord_sender: Callable = send_discord_article) -> dict[str, Any]:
    if not 1 <= max_ai_items <= 20 or not 1 <= max_messages <= 10 or not 1 <= timeout <= 30:
        raise ValueError("news_limits_invalid")
    sources = load_sources(registry)
    if dry_run:
        no_ai = True
    ai_skipped = False
    if not no_ai and summarizer is _deepseek_summary and not os.environ.get("DEEPSEEK_API_KEY", "").strip():
        if allow_missing_ai:
            no_ai = True
            ai_skipped = True
        else:
            raise ValueError("DEEPSEEK_API_KEY_required_or_use_no_ai")
    enabled = {name for name, active in (("feishu", feishu), ("discord", discord)) if active}
    channels = {name: {"enabled": name in enabled, "sent": 0, "errors": 0, "pending": 0}
                for name in ("feishu", "discord")}
    senders = {"feishu": sender, "discord": discord_sender}
    if not dry_run:
        for name, validator, callback in (("feishu", _webhook, send_article),
                                           ("discord", discord_webhook, send_discord_article)):
            if name in enabled and senders[name] is callback:
                try:
                    validator()
                except ValueError:
                    channels[name].update(errors=1, error=f"official_{name}_webhook_required")
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
        for row in cache.values():
            delivered = row.setdefault("delivered_channels", {})
            if not isinstance(delivered, dict) or any(type(value) is not bool for value in delivered.values()):
                raise ValueError("news_delivery_state_invalid")
            # Older releases only delivered to Feishu. Never mark Discord sent
            # merely because the legacy all-purpose flag is true.
            if row.get("delivered") is True:
                delivered.setdefault("feishu", True)
            targets = row.get("delivery_targets", [])
            if not isinstance(targets, list) or any(name not in {"feishu", "discord"} for name in targets):
                raise ValueError("news_delivery_state_invalid")
            row["delivery_targets"] = sorted(enabled | set(targets))
        removable = sorted((key for key, row in cache.items() if not _pending_delivery(row, enabled)),
                           key=lambda key: cache[key].get("seen_at", 0))
        for key in removable[:max(0, len(cache) - MAX_CACHE)]:
            cache.pop(key)
        cache_full_skipped = 0
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
                        if len(cache) >= MAX_CACHE:
                            removable = [key for key, row in cache.items() if not _pending_delivery(row, enabled)]
                            if not removable:
                                # Backpressure preserves a failed/pending outbox;
                                # fresh items can be picked up on a later poll.
                                cache_full_skipped += 1
                                continue
                            oldest = min(removable, key=lambda key: cache[key].get("seen_at", 0))
                            cache.pop(oldest)
                        cache[identity] = {
                            "url": url, "source": source["name"], "title": sanitize_external_text(entry.title, limit=240),
                            "summary": sanitize_external_text(entry.summary, limit=600),
                            "published_at": entry.published_at, "seen_at": time.time(), "ai_summary": "", "delivered": False,
                            "delivered_channels": {},
                            "delivery_targets": sorted(enabled),
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
        state = {"schema": "SignalHarborState/v1", "articles": cache}
        if not dry_run:
            _atomic_json(state_path, state)
        sent = 0
        for name in ("feishu", "discord"):
            if name not in enabled:
                continue
            outbox = [row for row in cache.values()
                      if row.get("ai_summary") and not row["delivered_channels"].get(name)]
            for row in outbox[:max_messages] if not dry_run and not channels[name].get("error") else []:
                try:
                    if not senders[name](row):
                        raise ValueError("message_rejected")
                    row["delivered_channels"][name] = True
                    if name == "feishu":
                        row["delivered"] = True
                    row.setdefault("delivery_error", {}).pop(name, None)
                    sent += 1
                    channels[name]["sent"] += 1
                    _atomic_json(state_path, state)
                except Exception as exc:
                    # Exception messages from HTTP libraries may contain the
                    # secret webhook URL. Persist only the exception class.
                    error = "message_rejected" if isinstance(exc, ValueError) and str(exc) == "message_rejected" else type(exc).__name__
                    row.setdefault("delivery_error", {})[name] = error
                    channels[name]["errors"] += 1
                    channels[name]["error"] = error
                    _atomic_json(state_path, state)
            channels[name]["pending"] = sum(not row["delivered_channels"].get(name)
                                             for row in cache.values())
        delivery_errors = sum(channel["errors"] for channel in channels.values())
        result = {
            "schema": "SignalHarborRun/v1", "completed_at": time.time(), "providers": statuses,
            "cached": len(cache), "summary_attempts": min(len(pending), max_ai_items),
            "summary_errors": ai_errors, "sent": sent, "delivery_errors": delivery_errors,
            "channels": channels, "dry_run": dry_run, "cache_full_skipped": cache_full_skipped,
            # A failed summary is isolated to its article; collection remains a
            # successful cycle and can retry the item on the next timer tick.
            "ok": any(row["status"] == "ok" for row in statuses) and not delivery_errors,
            "degraded": bool(ai_errors or delivery_errors or ai_skipped or cache_full_skipped
                              or any(row["status"] != "ok" for row in statuses)),
            "ai_skipped": ai_skipped,
        }
        if dry_run:
            result["preview"] = [{"title": row["title"], "summary": row["ai_summary"],
                                  "source": row["source"], "url": row["url"]}
                                 for row in cache.values() if row.get("ai_summary")][:max_messages]
        _atomic_json(state_dir / "last-run.json", result)
        return result
