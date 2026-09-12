from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Callable
from urllib.parse import urljoin, urlsplit

from ..models import AssetCandidate, IntelQuery, utc_now
from ..network import fetch_bytes_for_test
from ..scope import IntelScope

_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


class _Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:  # type: ignore[no-untyped-def]
        for key, value in attrs:
            if key.lower() in {"href", "src"} and value:
                self.links.append(value)


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        value = " ".join(data.split())
        if value:
            self.parts.append(value)


def _plain_text(value: str, limit: int = 600) -> str:
    parser = _TextExtractor()
    try:
        parser.feed(str(value or ""))
        text = " ".join(parser.parts)
    except Exception:
        text = re.sub(r"<[^>]+>", " ", str(value or ""))
    return " ".join(text.split())[:limit]


@dataclass(frozen=True)
class _FeedEntry:
    url: str
    title: str = ""
    summary: str = ""
    published_at: str = ""


def _element_text(element: ET.Element, names: set[str]) -> str:
    for child in element.iter():
        tag = child.tag.rsplit("}", 1)[-1].lower()
        if tag in names and (child.text or "").strip():
            return (child.text or "").strip()
    return ""


def _feed_entries(payload: bytes, source_url: str) -> list[_FeedEntry]:
    text = payload.decode("utf-8", errors="replace")
    entries: list[_FeedEntry] = []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        parser = _Links()
        parser.feed(text)
        values = [urljoin(source_url, item) for item in parser.links]
        values.extend(_URL_RE.findall(text))
        entries.extend(_FeedEntry(value, summary=_plain_text(text)) for value in values)
    else:
        item_elements = [element for element in root.iter() if element.tag.rsplit("}", 1)[-1].lower() in {"item", "entry"}]
        if not item_elements:
            item_elements = [root]
        for item in item_elements:
            link = ""
            for element in item.iter():
                tag = element.tag.rsplit("}", 1)[-1].lower()
                href = str(element.attrib.get("href") or "").strip()
                rel = str(element.attrib.get("rel") or "alternate").lower()
                if tag == "link" and href and rel in {"", "alternate"}:
                    link = urljoin(source_url, href)
                    break
                if tag in {"link", "guid", "url", "loc"} and (element.text or "").strip():
                    link = urljoin(source_url, (element.text or "").strip())
                    break
            title = _plain_text(_element_text(item, {"title"}), 300)
            summary = _plain_text(_element_text(item, {"description", "summary", "content", "encoded"}), 600)
            published = _plain_text(_element_text(item, {"published", "updated", "pubdate", "date"}), 80)
            if link:
                entries.append(_FeedEntry(link, title=title, summary=summary, published_at=published))
            combined = " ".join(filter(None, (title, summary)))
            for value in _URL_RE.findall(combined):
                entries.append(_FeedEntry(value, title=title, summary=summary, published_at=published))
    result: list[_FeedEntry] = []
    seen: set[str] = set()
    for entry in entries:
        value = entry.url.strip().rstrip(".,);]")
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            continue
        normalized = parsed._replace(fragment="").geturl()
        if normalized not in seen:
            seen.add(normalized)
            result.append(_FeedEntry(normalized, entry.title, entry.summary, entry.published_at))
    return result


class FeedProvider:
    def __init__(self, source_id: str, url: str, *, kind: str = "rss", tags: tuple[str, ...] = (), fetcher: Callable[..., bytes] | None = None) -> None:
        self.id = source_id
        self.url = url
        self.kind = kind
        self.tags = tuple(str(item).strip() for item in tags if str(item).strip())
        self.fetcher = fetcher or fetch_bytes_for_test

    def collect(self, query: IntelQuery, *, timeout: float, max_items: int) -> list[AssetCandidate]:
        raw = self.fetcher(self.url, timeout=timeout, max_bytes=2_000_000)
        scope = IntelScope(query)
        result: list[AssetCandidate] = []
        for entry in _feed_entries(raw, self.url):
            target_decision = scope.check_value(entry.url, "url")
            kind = "url" if target_decision.allowed else "article"
            result.append(
                AssetCandidate(
                    value=entry.url,
                    kind=kind,
                    source=self.id,
                    observed_at=utc_now(),
                    confidence=0.58 if self.kind == "rss" else 0.48,
                    evidence_ref=self.url,
                    tags=tuple(dict.fromkeys(("feed", self.kind, "target-reference" if kind == "url" else "public-intel", "untrusted-content", *self.tags))),
                    title=entry.title,
                    summary=entry.summary,
                    published_at=entry.published_at,
                )
            )
            if len(result) >= max_items:
                break
        return result
