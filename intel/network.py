from __future__ import annotations

import ipaddress
import socket
from typing import Mapping
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen


class UnsafeSourceUrl(ValueError):
    pass


def _resolved_public(host: str, port: int | None) -> bool:
    try:
        addresses = socket.getaddrinfo(host, port or 443, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise UnsafeSourceUrl("source_host_unresolvable") from exc
    if not addresses:
        raise UnsafeSourceUrl("source_host_unresolvable")
    for item in addresses:
        address = item[4][0]
        try:
            ip = ipaddress.ip_address(address)
        except ValueError as exc:
            raise UnsafeSourceUrl("source_host_invalid") from exc
        if not ip.is_global:
            raise UnsafeSourceUrl("source_host_not_public")
    return True


def validate_source_url(value: str, *, resolve: bool = True) -> str:
    parsed = urlsplit(str(value or "").strip())
    if parsed.scheme.lower() not in {"http", "https"} or parsed.username or parsed.password:
        raise UnsafeSourceUrl("source_url_must_be_public_http")
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host or any(char.isspace() for char in host) or host in {"localhost", "localhost.localdomain"} or host.endswith((".local", ".internal")):
        raise UnsafeSourceUrl("source_host_not_public")
    try:
        literal_ip = ipaddress.ip_address(host)
    except ValueError:
        literal_ip = None
    if literal_ip is not None and not literal_ip.is_global:
        raise UnsafeSourceUrl("source_host_not_public")
    try:
        port = parsed.port
    except ValueError as exc:
        raise UnsafeSourceUrl("source_url_invalid_port") from exc
    if resolve:
        _resolved_public(host, port)
    return parsed.geturl()


class _SafeRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        validate_source_url(newurl, resolve=True)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_url(url: str, *, timeout: float = 8.0, max_bytes: int = 2_000_000, user_agent: str = "pentest-agent-intel/1", headers: Mapping[str, str] | None = None) -> bytes:
    """Fetch a public feed only; redirects and oversized responses are bounded."""
    safe_url = validate_source_url(url, resolve=True)
    request_headers = {"User-Agent": user_agent, "Accept": "application/rss+xml, application/atom+xml, text/xml, text/html;q=0.9, */*;q=0.1"}
    request_headers.update({str(key): str(value) for key, value in (headers or {}).items()})
    request = Request(safe_url, headers=request_headers)
    opener = build_opener(_SafeRedirects())
    with opener.open(request, timeout=max(0.5, min(float(timeout), 60.0))) as response:
        content_length = response.headers.get("Content-Length")
        if content_length and int(content_length) > max_bytes:
            raise ValueError("source_response_too_large")
        data = response.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError("source_response_too_large")
        return data


def fetch_bytes_for_test(url: str, *, timeout: float, max_bytes: int, headers: Mapping[str, str] | None = None) -> bytes:
    """Explicit seam used by offline provider fixtures; never used by the CLI."""
    return fetch_url(url, timeout=timeout, max_bytes=max_bytes, headers=headers)
