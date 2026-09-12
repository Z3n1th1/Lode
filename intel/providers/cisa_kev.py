from __future__ import annotations

import json
from typing import Callable
from urllib.parse import quote

from ..models import AssetCandidate, IntelQuery, utc_now
from ..network import fetch_bytes_for_test


DEFAULT_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"


class CisaKevProvider:
    """Official CISA Known Exploited Vulnerabilities JSON feed."""

    def __init__(self, source_id: str = "builtin-cisa-kev", *, url: str = DEFAULT_URL, fetcher: Callable[..., bytes] | None = None) -> None:
        self.id = source_id
        self.url = url
        self.fetcher = fetcher or fetch_bytes_for_test

    def collect(self, query: IntelQuery, *, timeout: float, max_items: int) -> list[AssetCandidate]:
        del query
        raw = self.fetcher(self.url, timeout=timeout, max_bytes=8_000_000)
        payload = json.loads(raw.decode("utf-8", errors="replace"))
        rows = payload.get("vulnerabilities") if isinstance(payload, dict) else None
        if not isinstance(rows, list):
            raise ValueError("cisa_kev_payload_invalid")
        result: list[AssetCandidate] = []
        for row in rows[:max_items]:
            if not isinstance(row, dict):
                continue
            cve = str(row.get("cveID") or "").strip().upper()
            if not cve.startswith("CVE-"):
                continue
            vendor = str(row.get("vendorProject") or "").strip()
            product = str(row.get("product") or "").strip()
            name = str(row.get("vulnerabilityName") or "").strip()
            action = str(row.get("requiredAction") or "").strip()
            ransomware = str(row.get("knownRansomwareCampaignUse") or "").strip()
            notes = str(row.get("notes") or "").strip()
            title = f"{cve} {vendor} {product} {name}".strip()[:300]
            summary = " ".join(part for part in (action, f"Ransomware use: {ransomware}" if ransomware else "", notes) if part)[:1000]
            result.append(AssetCandidate(
                value=f"{CATALOG_URL}?cve={quote(cve)}",
                kind="cve",
                source=self.id,
                observed_at=utc_now(),
                published_at=str(row.get("dateAdded") or "").strip(),
                confidence=0.95,
                evidence_ref=self.url,
                title=title,
                summary=summary,
                tags=("cve", "cisa-kev", "known-exploited", "public-intel"),
            ))
        return result

