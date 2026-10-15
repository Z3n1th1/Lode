"""Parse ARL-Friend / ARL task exports into AssetCandidates.

The export is treated as an offline file: nothing here talks to Mongo, RabbitMQ
or the ARL HTTP API. Scope filtering happens in the intel runner afterwards.
"""
from __future__ import annotations

import json
import re
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

from .models import AssetCandidate, utc_now
from .scope import normalize_host


# Distilled CNAME suffixes from ARL cdn_info.json plus the CDNs this operator
# already treats as never-collect. IP CIDR tables stay out: they are huge and
# the hunt wants exact hosts, not a netblock walk.
CDN_SUFFIXES: tuple[str, ...] = (
    "cloudflare.com", "cloudfront.net", "akamai.net", "akamaiedge.net",
    "akamaized.net", "edgekey.net", "edgesuite.net", "fastly.net",
    "fastlylb.net", "cdn77.org", "cdn77.net",
    "bytegoofy.com", "byted-static.com", "douyinstatic.com", "ecombdstatic.com",
    "pstatp.com", "byteimg.com",
    "bdydns.com", "yunjiasu-cdn.net", "jomodns.com",
    "alicdn.com", "kunlun.com", "kunlunar.com",
    "qcloudcdn.com", "myqcloud.com", "cdntip.com", "tcdn.qq.com",
    "360buyimg.com", "jdcdn.com", "jcloudcs.com",
    "unpkg.com", "jsdelivr.net", "cdnjs.cloudflare.com",
)

_HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$", re.I)


def is_cdn_host(value: str) -> bool:
    host = normalize_host(value)
    if "://" in host:
        host = normalize_host(urlsplit(host).hostname or "")
    if not host:
        return False
    return any(host == suffix or host.endswith("." + suffix) for suffix in CDN_SUFFIXES)


def _row_looks_like_arl(row: Mapping[str, Any]) -> bool:
    """True for one ARL asset row. Lode candidates carry ``value``/``kind`` instead."""
    if "site" in row or "fld" in row:
        return True
    if "value" in row or "kind" in row:
        return False
    return any(key in row for key in ("domain", "ip"))


def looks_like_arl(value: Any) -> bool:
    """True when a decoded JSON object is an ARL-shaped export, not a candidate list."""
    if isinstance(value, Mapping):
        if _row_looks_like_arl(value):
            return True
        nested = value.get("data")
        if isinstance(nested, Mapping) and isinstance(nested.get("items"), list):
            rows = [item for item in nested["items"] if isinstance(item, Mapping)]
            return bool(rows) and _row_looks_like_arl(rows[0])
        if isinstance(value.get("items"), list):
            rows = [item for item in value["items"] if isinstance(item, Mapping)]
            return bool(rows) and _row_looks_like_arl(rows[0])
        return False
    if isinstance(value, list) and value and isinstance(value[0], Mapping):
        return _row_looks_like_arl(value[0])
    return False


def _rows(value: Any) -> list[Mapping[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, Mapping)]
    if not isinstance(value, Mapping):
        return []
    nested = value.get("data")
    if isinstance(nested, Mapping) and isinstance(nested.get("items"), list):
        return [item for item in nested["items"] if isinstance(item, Mapping)]
    if isinstance(value.get("items"), list):
        return [item for item in value["items"] if isinstance(item, Mapping)]
    return [value]


def _host_from_site(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if "://" in text:
        return normalize_host(urlsplit(text).hostname or "")
    return normalize_host(text.split("/", 1)[0])


def parse_arl(
    value: Any,
    *,
    source: str = "arl-export",
    max_items: int = 200,
    drop_cdn: bool = True,
) -> list[AssetCandidate]:
    """Turn an ARL export into hostname/url candidates. CDN hosts are dropped."""
    result: list[AssetCandidate] = []
    seen: set[str] = set()
    for row in _rows(value):
        site = str(row.get("site") or row.get("url") or "").strip()
        domain = str(row.get("domain") or row.get("fld") or "").strip()
        ip = str(row.get("ip") or "").strip()
        title = str(row.get("title") or row.get("http_title") or "").strip()[:300]
        tags = ["arl-export"]
        if site:
            host = _host_from_site(site)
            kind, raw = ("url", site if "://" in site else "https://" + site)
        elif domain:
            host, kind, raw = normalize_host(domain), "hostname", normalize_host(domain)
        elif ip:
            host, kind, raw = ip, "ip", ip
        else:
            continue
        host = host or _host_from_site(raw)
        if not host or host in seen:
            continue
        if drop_cdn and kind != "ip" and is_cdn_host(host):
            continue
        if kind == "hostname" and _HOST_RE.fullmatch(host) is None:
            continue
        seen.add(host)
        if row.get("status") or row.get("http_status"):
            tags.append("http-observed")
        if title:
            tags.append("titled")
        result.append(
            AssetCandidate(
                value=raw,
                kind=kind,
                source=source,
                observed_at=utc_now(),
                confidence=0.84,
                evidence_ref=str(row.get("site") or domain or ip)[:500],
                tags=tuple(tags),
                title=title,
                summary="ARL export asset",
            )
        )
        if len(result) >= max_items:
            break
    return result


def parse_arl_text(text: str, *, source: str = "arl-export", max_items: int = 200) -> list[AssetCandidate]:
    text = str(text or "").strip()
    if not text:
        return []
    try:
        decoded = json.loads(text)
    except json.JSONDecodeError:
        hosts = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            hosts.append({"site": line} if "://" in line or "." in line else {"ip": line})
        decoded = hosts
    return parse_arl(decoded, source=source, max_items=max_items)


def exact_hosts(candidates: Iterable[AssetCandidate], *, drop_cdn: bool = True) -> list[str]:
    """Deduped hostnames suitable for a Lode ``allowed_hosts`` slice."""
    out: list[str] = []
    seen: set[str] = set()
    for item in candidates:
        host = _host_from_site(item.value) if item.kind != "ip" else ""
        if item.kind == "ip":
            continue
        if not host or host in seen:
            continue
        if drop_cdn and is_cdn_host(host):
            continue
        seen.add(host)
        out.append(host)
    return out
