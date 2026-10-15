"""GET-only management-plane fingerprints distilled from ARL-Friend identify plugins.

Existence probes, not exploits. Brute-force, Nuclei, NPoC and non-HTTP service
checks stay out of this module on purpose.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, Sequence
from urllib.parse import urljoin, urlsplit, urlunsplit

from .models import AssetCandidate, utc_now


@dataclass(frozen=True)
class FingerprintProbe:
    path: str
    name: str
    markers: tuple[str, ...]
    tags: tuple[str, ...]


# One representative path per family. Extra variants belong in ARL itself; here
# they would just burn the shared request budget.
PROBES: tuple[FingerprintProbe, ...] = (
    FingerprintProbe("/nacos/", "nacos", ("<title>Nacos</title>",), ("nacos", "management")),
    FingerprintProbe(
        "/xxl-job-admin/toLogin",
        "xxl-job",
        ("<b>XXL</b>JOB", "xxl-job-admin"),
        ("xxl", "management"),
    ),
    FingerprintProbe("/api/systeminfo", "harbor", ('"harbor_version"',), ("harbor", "registry")),
    FingerprintProbe(
        "/harbor/api/systeminfo",
        "harbor",
        ('"harbor_version"',),
        ("harbor", "registry"),
    ),
    FingerprintProbe(
        "/actuator/health",
        "actuator-health",
        ('"status":"UP"', '"status": "UP"'),
        ("actuator", "health"),
    ),
    FingerprintProbe("/grafana/login", "grafana", ("Grafana</title>",), ("grafana", "management")),
    FingerprintProbe(
        "/console/css/test.css",
        "weblogic",
        ("WLS Administration Console",),
        ("weblogic", "management"),
    ),
    FingerprintProbe(
        "/help/sys/help.html",
        "ecology",
        ("btn_help_click",),
        ("ecology", "oa"),
    ),
)


def seed_paths() -> tuple[str, ...]:
    """Unique probe paths for ``discover_surface(..., extra_seeds=)``."""
    return tuple(dict.fromkeys(item.path for item in PROBES))


def match_body(text: str) -> tuple[str, ...]:
    """Which probe names the body confirms. Empty when it is just a soft-404 shell."""
    if not text:
        return ()
    lower = text.lower()
    if "<html" in lower and "nacos" not in lower and "grafana" not in lower and "xxl" not in lower:
        # SPA catch-alls echo the same index for every path; markers still win below.
        pass
    hits: list[str] = []
    for probe in PROBES:
        if any(marker in text for marker in probe.markers):
            hits.append(probe.name)
    return tuple(dict.fromkeys(hits))


def _base_url(target: str) -> str:
    raw = str(target or "").strip()
    if raw and "://" not in raw:
        raw = "https://" + raw
    parsed = urlsplit(raw)
    return urlunsplit((parsed.scheme.lower() or "https", parsed.netloc, "", "", ""))


Fetcher = Callable[..., tuple[int, str, dict[str, str]]]


def probe_host(
    target: str,
    *,
    fetcher: Fetcher,
    timeout: float = 8.0,
    probes: Sequence[FingerprintProbe] = PROBES,
) -> list[AssetCandidate]:
    """Run the catalog against one authorized origin. Caller enforces scope."""
    base = _base_url(target)
    if not base:
        return []
    found: list[AssetCandidate] = []
    seen: set[str] = set()
    for probe in probes:
        url = urljoin(base + "/", probe.path.lstrip("/"))
        try:
            status, body, _headers = fetcher(url, timeout=timeout, max_bytes=200_000)
        except TypeError:
            status, body, _headers = fetcher(url)
        except Exception:
            continue
        if status == 0 or not body:
            continue
        if not any(marker in body for marker in probe.markers):
            continue
        key = f"{probe.name}:{urlsplit(url).path}"
        if key in seen:
            continue
        seen.add(key)
        found.append(
            AssetCandidate(
                value=url,
                kind="url",
                source="arl-fingerprint",
                observed_at=utc_now(),
                confidence=0.9,
                evidence_ref=url,
                tags=("fingerprint",) + probe.tags,
                title=probe.name,
                summary=f"{probe.name} fingerprint on HTTP {status}",
            )
        )
    return found


def probe_targets(
    targets: Iterable[str],
    *,
    fetcher: Fetcher,
    timeout: float = 8.0,
    max_items: int = 200,
) -> list[AssetCandidate]:
    result: list[AssetCandidate] = []
    for target in targets:
        result.extend(probe_host(target, fetcher=fetcher, timeout=timeout))
        if len(result) >= max_items:
            return result[:max_items]
    return result
