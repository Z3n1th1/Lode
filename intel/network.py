from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
import time
from typing import Mapping
from urllib.error import HTTPError
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit


class UnsafeSourceUrl(ValueError):
    pass


_FAKE_IP_RANGE = ipaddress.ip_network("198.18.0.0/15")
# Fixed bootstrap addresses avoid asking the intercepted system resolver how to
# reach the resolver. HTTPS still verifies each provider's hostname and certificate.
_DOH_ENDPOINTS = (
    ("dns.alidns.com", "223.5.5.5", "/resolve"),
    ("dns.pub", "1.12.12.12", "/dns-query"),
)
_DOH_MAX_BYTES = 65_536
_MAX_REDIRECTS = 5


class _Deadline:
    def __init__(self, timeout: float) -> None:
        self.end = time.monotonic() + timeout

    def remaining(self) -> float:
        remaining = self.end - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("source_request_timed_out")
        return remaining


def _public_ip(address: str) -> str:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError as exc:
        raise UnsafeSourceUrl("source_host_invalid") from exc
    if not ip.is_global or ip.is_multicast or ip.is_reserved:
        raise UnsafeSourceUrl("source_host_not_public")
    return str(ip)


def _connect_addresses(addresses: tuple[str, ...], port: int, deadline: _Deadline) -> socket.socket:
    last_error: OSError | None = None
    for index, address in enumerate(addresses):
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            # Connect to the validated numeric address without a second DNS lookup.
            sock.settimeout(max(0.1, deadline.remaining() / (len(addresses) - index)))
            sock.connect((address, port))
            sock.settimeout(deadline.remaining())
            return sock
        except OSError as exc:
            last_error = exc
            sock.close()
    if last_error is not None:
        raise last_error
    raise UnsafeSourceUrl("source_host_unresolvable")


def _connection(host: str, port: int, addresses: tuple[str, ...], *, secure: bool, deadline: _Deadline):
    if secure:
        connection = http.client.HTTPSConnection(
            host, port, timeout=deadline.remaining(), context=ssl.create_default_context()
        )
    else:
        connection = http.client.HTTPConnection(host, port, timeout=deadline.remaining())
    # HTTPSConnection uses the original hostname for SNI and certificate checking;
    # only the socket destination is pinned. No environment/OS HTTP proxy is used.
    connection._create_connection = lambda *args, **kwargs: _connect_addresses(addresses, port, deadline)
    return connection


def _read_bounded(response, connection, deadline: _Deadline, max_bytes: int) -> bytes:
    content_length = response.headers.get("Content-Length")
    if content_length and int(content_length) > max_bytes:
        raise ValueError("source_response_too_large")
    chunks: list[bytes] = []
    size = 0
    while True:
        remaining = deadline.remaining()
        # HTTPConnection releases its reference when a server sends Connection:
        # close; the response still owns the socket until its body has been read.
        response_socket = connection.sock
        if response_socket is None and response.fp is not None:
            response_socket = getattr(getattr(response.fp, "raw", None), "_sock", None)
        if response_socket is not None:
            response_socket.settimeout(remaining)
        chunk = response.read1(min(65_536, max_bytes + 1 - size))
        if not chunk:
            return b"".join(chunks)
        size += len(chunk)
        if size > max_bytes:
            raise ValueError("source_response_too_large")
        chunks.append(chunk)


def _doh_addresses(host: str, deadline: _Deadline) -> tuple[str, ...]:
    last_error: Exception | None = None
    for resolver_host, resolver_ip, path in _DOH_ENDPOINTS:
        # Leave time for the other provider and the feed when a resolver is down.
        resolver_deadline = _Deadline(min(3.0, deadline.remaining()))
        for record_type in (1, 28):
            connection = _connection(resolver_host, 443, (resolver_ip,), secure=True, deadline=resolver_deadline)
            response = None
            try:
                query = urlencode({"name": host, "type": record_type})
                connection.request("GET", f"{path}?{query}", headers={"Accept": "application/dns-json"})
                if connection.sock is not None:
                    connection.sock.settimeout(resolver_deadline.remaining())
                response = connection.getresponse()
                # Never follow a resolver redirect to an untrusted endpoint.
                if response.status != 200:
                    raise ValueError("source_dns_http_error")
                payload = json.loads(_read_bounded(response, connection, resolver_deadline, _DOH_MAX_BYTES))
                if not isinstance(payload, dict) or payload.get("Status") != 0 or payload.get("TC"):
                    raise ValueError("source_dns_lookup_failed")
                answers = payload.get("Answer", [])
                if not isinstance(answers, list):
                    raise ValueError("source_dns_invalid_response")
                addresses = tuple(dict.fromkeys(
                    _public_ip(str(answer.get("data", "")))
                    for answer in answers
                    if isinstance(answer, dict) and answer.get("type") in (1, 28)
                ))
                if addresses:
                    return addresses
            except UnsafeSourceUrl:
                # A private answer is a denial, never a reason to try a resolver
                # that might return a more convenient answer.
                raise
            except (OSError, ValueError, http.client.HTTPException) as exc:
                last_error = exc
                break
            finally:
                if response is not None:
                    response.close()
                connection.close()
    raise UnsafeSourceUrl("source_host_unresolvable_via_doh") from last_error


def _resolve_public_addresses(host: str, port: int, deadline: _Deadline) -> tuple[str, ...]:
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        return (_public_ip(str(literal)),)
    try:
        answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise UnsafeSourceUrl("source_host_unresolvable") from exc
    if not answers:
        raise UnsafeSourceUrl("source_host_unresolvable")
    addresses: list[str] = []
    fake_ip = False
    for item in answers:
        address = item[4][0]
        try:
            ip = ipaddress.ip_address(address)
        except ValueError as exc:
            raise UnsafeSourceUrl("source_host_invalid") from exc
        if isinstance(ip, ipaddress.IPv4Address) and ip in _FAKE_IP_RANGE:
            fake_ip = True
        else:
            addresses.append(_public_ip(address))
    if fake_ip:
        # Clash TUN's benchmark-range answers are never valid destinations. Only
        # a fresh, authenticated public answer can authorize a connection.
        return _doh_addresses(host, deadline)
    return tuple(dict.fromkeys(addresses))


def _resolved_public(host: str, port: int | None) -> bool:
    _resolve_public_addresses(host, port or 443, _Deadline(8.0))
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
    if literal_ip is not None:
        _public_ip(str(literal_ip))
    try:
        port = parsed.port
    except ValueError as exc:
        raise UnsafeSourceUrl("source_url_invalid_port") from exc
    if resolve:
        _resolved_public(host, port)
    return parsed.geturl()


def fetch_url(url: str, *, timeout: float = 8.0, max_bytes: int = 2_000_000, user_agent: str = "pentest-agent-intel/1", headers: Mapping[str, str] | None = None) -> bytes:
    """Fetch a public feed with pinned DNS, verified TLS and bounded redirects/body."""
    if max_bytes < 0:
        raise ValueError("source_response_invalid_limit")
    deadline = _Deadline(max(0.5, min(float(timeout), 60.0)))
    current_url = validate_source_url(url, resolve=False)
    request_headers = {"User-Agent": user_agent, "Accept": "application/rss+xml, application/atom+xml, text/xml, text/html;q=0.9, */*;q=0.1"}
    request_headers.update({str(key): str(value) for key, value in (headers or {}).items()})
    request_headers = {key: value for key, value in request_headers.items() if key.lower() not in {"host", "proxy-authorization"}}
    for redirect_count in range(_MAX_REDIRECTS + 1):
        parsed = urlsplit(current_url)
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        addresses = _resolve_public_addresses(host, port, deadline)
        connection = _connection(host, port, addresses, secure=parsed.scheme == "https", deadline=deadline)
        response = None
        try:
            target = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
            connection.request("GET", target, headers=request_headers)
            if connection.sock is not None:
                connection.sock.settimeout(deadline.remaining())
            response = connection.getresponse()
            location = response.headers.get("Location")
            if response.status in {301, 302, 303, 307, 308} and location:
                if redirect_count >= _MAX_REDIRECTS:
                    raise ValueError("source_too_many_redirects")
                next_url = validate_source_url(urljoin(current_url, location), resolve=False)
                next_parsed = urlsplit(next_url)
                if (parsed.scheme, parsed.netloc) != (next_parsed.scheme, next_parsed.netloc):
                    request_headers = {key: value for key, value in request_headers.items() if key.lower() not in {"authorization", "cookie"}}
                current_url = next_url
                continue
            if not 200 <= response.status < 300:
                raise HTTPError(current_url, response.status, response.reason, response.headers, None)
            return _read_bounded(response, connection, deadline, max_bytes)
        finally:
            if response is not None:
                response.close()
            connection.close()
    raise ValueError("source_too_many_redirects")


def fetch_bytes_for_test(url: str, *, timeout: float, max_bytes: int, headers: Mapping[str, str] | None = None) -> bytes:
    """Explicit seam used by offline provider fixtures; never used by the CLI."""
    return fetch_url(url, timeout=timeout, max_bytes=max_bytes, headers=headers)
