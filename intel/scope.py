from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .models import AssetCandidate, IntelQuery

_HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$", re.IGNORECASE)
PUBLIC_INTEL_KINDS = frozenset({"article", "advisory", "cve", "poc", "social_post"})


def normalize_host(value: str) -> str:
    return str(value or "").strip().lower().strip("[]").rstrip(".")


def normalize_scope_host(value: str) -> str:
    item = normalize_host(value)
    if "://" in item:
        item = normalize_host(urlsplit(item).hostname or "")
    return item


def host_matches(host: str, scope_host: str, *, descendants: bool = True) -> bool:
    host = normalize_host(host)
    scope_host = normalize_scope_host(scope_host)
    wildcard = scope_host.startswith("*.")
    if wildcard:
        scope_host = scope_host[2:]
    if not host or not scope_host:
        return False
    if host == scope_host:
        return not wildcard or descendants
    return descendants and host.endswith("." + scope_host)


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str


class IntelScope:
    def __init__(self, query: IntelQuery) -> None:
        query.require_authorization()
        self.query = query

    def check_host(self, value: str) -> ScopeDecision:
        host = normalize_host(value)
        if not host or (not is_ip(host) and _HOST_RE.fullmatch(host) is None):
            return ScopeDecision(False, "invalid_host")
        forbidden = self.query.forbidden + self.query.forbidden_hosts
        for item in forbidden:
            if host_matches(host, item, descendants=True):
                return ScopeDecision(False, f"forbidden:{normalize_scope_host(item)}")
        if is_ip(host):
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                return ScopeDecision(False, "invalid_ip")
            for item in self.query.allowed_ips:
                try:
                    if "/" in item and address in ipaddress.ip_network(item, strict=False):
                        return ScopeDecision(True, f"allowed_ip_range:{item}")
                    if address == ipaddress.ip_address(item):
                        return ScopeDecision(True, f"allowed_ip:{item}")
                except ValueError:
                    continue
            return ScopeDecision(False, "ip_not_in_scope")
        for item in self.query.allowed_domains:
            if host_matches(host, item, descendants=True):
                return ScopeDecision(True, f"allowed_domain:{normalize_scope_host(item)}")
        for item in self.query.allowed_hosts:
            exact = not normalize_scope_host(item).startswith("*.")
            if host_matches(host, item, descendants=not exact):
                return ScopeDecision(True, f"allowed_host:{normalize_scope_host(item)}")
        return ScopeDecision(False, "host_not_in_scope")

    def check_value(self, value: str, kind: str) -> ScopeDecision:
        if kind == "hostname" or kind == "ip":
            return self.check_host(value)
        if kind == "url":
            parsed = urlsplit(value if "://" in value else "https://" + value)
            if parsed.scheme.lower() not in {"http", "https"}:
                return ScopeDecision(False, "unsupported_url_scheme")
            if parsed.username or parsed.password:
                return ScopeDecision(False, "url_credentials_not_allowed")
            try:
                parsed.port
            except ValueError:
                return ScopeDecision(False, "invalid_url_port")
            return self.check_host(parsed.hostname or "")
        return ScopeDecision(False, "kind_requires_review")

    def check_candidate(self, candidate: AssetCandidate) -> ScopeDecision:
        # Public intelligence references are stored but never fetched by the
        # runner.  They are not target assets, so target-domain scope does not
        # apply to them.  Active follow-up still requires a TargetCard.
        if candidate.kind in PUBLIC_INTEL_KINDS:
            parsed = urlsplit(candidate.value)
            if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
                return ScopeDecision(False, "public_intel_url_invalid")
            if parsed.username or parsed.password:
                return ScopeDecision(False, "public_intel_credentials_not_allowed")
            return ScopeDecision(True, "public_intel_reference")
        return self.check_value(candidate.value, candidate.kind)
