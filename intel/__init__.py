"""Scope-bound, passive threat-intelligence collection for authorized programs.

The package deliberately has no dependency on Strix, the LLM client, Feishu, or
the WebUI.  Providers return candidates; the runner owns scope filtering,
deduplication, ranking, and durable replayable output.
"""

from .models import AssetCandidate, IntelQuery, ProviderStatus, RunReport, WatchSummary
from .runner import collect, providers_from_registry, run_watch

__all__ = [
    "AssetCandidate",
    "IntelQuery",
    "ProviderStatus",
    "RunReport",
    "WatchSummary",
    "collect",
    "providers_from_registry",
    "run_watch",
]
