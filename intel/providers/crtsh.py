from __future__ import annotations

import json
from typing import Callable
from urllib.parse import quote

from ..models import AssetCandidate, IntelQuery, utc_now
from ..scope import host_matches, normalize_host
from ..network import fetch_bytes_for_test


class CrtShProvider:
    id = "crtsh"

    def __init__(self, fetcher: Callable[..., bytes] | None = None, *, source_id: str = "crtsh") -> None:
        self.id = source_id
        self.fetcher = fetcher or fetch_bytes_for_test

    def collect(self, query: IntelQuery, *, timeout: float, max_items: int) -> list[AssetCandidate]:
        result: list[AssetCandidate] = []
        seen: set[str] = set()
        # CT lookups are only useful for domain scopes.  Exact TargetCard hosts
        # do not authorize a whole suffix, so do not expand them here.
        for domain in query.allowed_domains:
            domain = normalize_host(domain).removeprefix("*.")
            if not domain:
                continue
            url = f"https://crt.sh/?q={quote('%.{}'.format(domain))}&output=json"
            raw = self.fetcher(url, timeout=timeout, max_bytes=5_000_000)
            rows = json.loads(raw.decode("utf-8", errors="replace"))
            if not isinstance(rows, list):
                continue
            for item in rows:
                if not isinstance(item, dict):
                    continue
                for field in ("name_value", "common_name"):
                    value = item.get(field)
                    for line in str(value or "").splitlines():
                        host = normalize_host(line.replace("*.", ""))
                        if not host or host in seen or not host_matches(host, domain):
                            continue
                        if len(host) > 253 or any(part == "" for part in host.split(".")):
                            continue
                        seen.add(host)
                        tags = ["certificate-transparency"]
                        if item.get("not_before") or item.get("entry_timestamp"):
                            tags.append("certificate-observed")
                        result.append(
                            AssetCandidate(
                                value=host,
                                kind="hostname",
                                source=self.id,
                                observed_at=str(item.get("entry_timestamp") or item.get("not_before") or utc_now()),
                                confidence=0.82,
                                evidence_ref=url,
                                tags=tuple(tags),
                            )
                        )
                        if len(result) >= max_items:
                            return result
        return result
