from __future__ import annotations

from urllib.parse import urlsplit

from ..models import AssetCandidate, IntelQuery, utc_now


class SeedProvider:
    def __init__(self, source_id: str = "seed") -> None:
        self.id = source_id

    def collect(self, query: IntelQuery, *, timeout: float, max_items: int) -> list[AssetCandidate]:
        del timeout
        result: list[AssetCandidate] = []
        for seed in query.seed_urls[:max_items]:
            parsed = urlsplit(seed if "://" in seed else "https://" + seed)
            if parsed.hostname:
                result.append(
                    AssetCandidate(
                        value=seed,
                        kind="url",
                        source=self.id,
                        observed_at=utc_now(),
                        confidence=1.0,
                        evidence_ref="scope.seed_urls",
                        tags=("scope-seed",),
                    )
                )
        return result
