from __future__ import annotations

import json
import os
import re
from typing import Callable
from urllib.parse import urlencode

from ..models import AssetCandidate, IntelQuery, utc_now
from ..network import fetch_bytes_for_test
from ..scope import IntelScope

_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
DEFAULT_API_URL = "https://api.x.com/2/tweets/search/recent"


class TwitterProvider:
    """Official X recent-search provider; bearer token is read only from env."""

    def __init__(self, source_id: str, query: str, *, api_url: str = DEFAULT_API_URL, fetcher: Callable[..., bytes] | None = None, bearer_token: str | None = None) -> None:
        self.id = source_id
        self.query = str(query or "").strip()[:256]
        self.api_url = api_url or DEFAULT_API_URL
        self.fetcher = fetcher or fetch_bytes_for_test
        self.bearer_token = bearer_token or os.environ.get("X_BEARER_TOKEN") or os.environ.get("TWITTER_BEARER_TOKEN") or ""

    def collect(self, query: IntelQuery, *, timeout: float, max_items: int) -> list[AssetCandidate]:
        if not self.bearer_token:
            raise RuntimeError("twitter_bearer_token_required")
        if not self.query:
            raise RuntimeError("twitter_query_required")
        params = urlencode({"query": self.query, "max_results": max(10, min(max_items, 100)), "tweet.fields": "created_at,entities"})
        raw = self.fetcher(f"{self.api_url}?{params}", timeout=timeout, max_bytes=2_000_000, headers={"Authorization": f"Bearer {self.bearer_token}"})
        payload = json.loads(raw.decode("utf-8", errors="replace"))
        scope = IntelScope(query)
        result: list[AssetCandidate] = []
        seen: set[str] = set()
        for tweet in (payload.get("data") or [])[:max_items]:
            if not isinstance(tweet, dict):
                continue
            tweet_id = str(tweet.get("id") or "")
            evidence = f"https://x.com/i/web/status/{tweet_id}" if tweet_id else ""
            tweet_text = " ".join(str(tweet.get("text") or "").split())[:1000]
            if evidence:
                result.append(AssetCandidate(
                    value=evidence,
                    kind="social_post",
                    source=self.id,
                    observed_at=str(tweet.get("created_at") or utc_now()),
                    published_at=str(tweet.get("created_at") or ""),
                    confidence=0.4,
                    evidence_ref=evidence,
                    title=tweet_text[:160],
                    summary=tweet_text,
                    tags=("social", "twitter", "public-intel", "untrusted-content"),
                ))
                seen.add(evidence)
                if len(result) >= max_items:
                    return result
            values = _URL_RE.findall(tweet_text)
            for entity in ((tweet.get("entities") or {}).get("urls") or []):
                if isinstance(entity, dict) and entity.get("expanded_url"):
                    values.append(str(entity["expanded_url"]))
            for value in values:
                value = value.rstrip(".,);]")
                if value in seen:
                    continue
                seen.add(value)
                kind = "url" if scope.check_value(value, "url").allowed else "article"
                result.append(AssetCandidate(
                    value=value,
                    kind=kind,
                    source=self.id,
                    observed_at=str(tweet.get("created_at") or utc_now()),
                    confidence=0.45,
                    evidence_ref=evidence,
                    title=tweet_text[:160],
                    summary=tweet_text,
                    published_at=str(tweet.get("created_at") or ""),
                    tags=("social", "twitter", "target-reference" if kind == "url" else "public-intel", "untrusted-content"),
                ))
                if len(result) >= max_items:
                    return result
        return result
