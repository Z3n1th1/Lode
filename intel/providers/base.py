from __future__ import annotations

from typing import Protocol

from ..models import AssetCandidate, IntelQuery


class IntelProvider(Protocol):
    id: str

    def collect(self, query: IntelQuery, *, timeout: float, max_items: int) -> list[AssetCandidate]:
        ...
