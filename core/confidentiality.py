"""Confidentiality boundary for third-party notification channels.

The local WebUI and workspace may contain complete reports.  Feishu and other
notification transports must only receive operational metadata and public
intelligence summaries, never report bodies, evidence, credentials, or raw
request/response material.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit


EXTERNAL_TEXT_LIMIT = 1500
_REDACTED = "[已脱敏]"
_LOCAL_ONLY = "[本地保密内容已拦截]"
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(api[-_ ]?key|access[-_ ]?token|refresh[-_ ]?token|client[-_ ]?secret|"
    r"password|passwd|secret|session(?:id)?|authorization|token)\b"
    r"(\s*[:=]\s*)([^\s,;]+|\"[^\"]*\"|'[^']*')"
)
_AUTH_VALUE = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}")
_COOKIE_LINE = re.compile(r"(?im)^(\s*(?:set-)?cookie\s*:\s*).*$")
_PRIVATE_KEY = re.compile(
    r"-----BEGIN [^-\r\n]*(?:PRIVATE KEY|OPENSSH PRIVATE KEY)-----[\s\S]*?"
    r"-----END [^-\r\n]*(?:PRIVATE KEY|OPENSSH PRIVATE KEY)-----",
    re.IGNORECASE,
)
_CODE_FENCE = re.compile(r"```[\s\S]*?```", re.MULTILINE)
_RAW_HTTP = re.compile(
    r"(?ims)^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE)\s+\S+\s+HTTP/\d(?:\.\d)?[^\r\n]*$[\s\S]*$"
    r"|^HTTP/\d(?:\.\d)?\s+\d{3}[^\r\n]*$[\s\S]*$"
)
_REPORT_SECTION = re.compile(
    r"(?ims)^\s{0,3}#{1,6}\s*(?:完整)?(?:渗透测试|漏洞|安全审计)?报告\b[\s\S]*$"
    r"|^\s{0,3}#{1,6}\s*(?:penetration\s+test|vulnerability|security\s+audit)\s+report\b[\s\S]*$"
    r"|^\s{0,3}#{1,6}\s*(?:复现步骤|原始证据|请求包|响应包|proof\s+of\s+concept)\b[\s\S]*$"
)
_SENSITIVE_PAYLOAD_KEY = re.compile(
    r"(?i)(?:authorization|cookie|credential|evidence|password|private_?key|raw|"
    r"report|request|response|secret|session|token)"
)
_WINDOWS_PATH = re.compile(r"(?i)(?<![A-Za-z0-9])(?:[A-Z]:\\|\\\\)[^\r\n<>|\"]+")
_HOME_PATH = re.compile(r"(?<![A-Za-z0-9])/(?:home|Users|root)/[^\s<>\"]+")
_URL = re.compile(r"https?://[^\s<>\"]+", re.IGNORECASE)


def _sanitize_url(match: re.Match[str]) -> str:
    raw = match.group(0)
    trailing = ""
    while raw and raw[-1] in ".,;:!?)]}，。；：！？）】":
        trailing = raw[-1] + trailing
        raw = raw[:-1]
    try:
        parts = urlsplit(raw)
    except ValueError:
        return _REDACTED + trailing
    host = parts.hostname or ""
    if not host:
        return _REDACTED + trailing
    try:
        port = f":{parts.port}" if parts.port is not None else ""
    except ValueError:
        port = ""
    netloc = host + port
    # Query values often carry session state, private identifiers, or signed
    # URLs.  Public intelligence links remain useful without them.
    clean = urlunsplit((parts.scheme.lower(), netloc, parts.path, "", ""))
    return clean + trailing


def external_target_label(value: Any) -> str:
    """Return a stable host-only label suitable for an external notification."""
    text = str(value or "").strip()
    if not text:
        return "未标注目标"
    candidate = text if "://" in text else f"//{text}"
    try:
        parts = urlsplit(candidate)
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        host, port = "", None
    if host:
        return f"{host}:{port}" if port is not None else host
    safe = re.sub(r"[^A-Za-z0-9._:-]", "_", text)[:120]
    return safe or "未标注目标"


def safe_external_identifier(value: Any, *, limit: int = 120) -> str:
    """Allow only identifier characters used by task/finding references."""
    safe = re.sub(r"[^A-Za-z0-9._:-]", "_", str(value or "").strip())
    return (safe[: max(1, limit)] or "unknown")


def sanitize_external_text(value: Any, *, limit: int = EXTERNAL_TEXT_LIMIT) -> str:
    """Redact material that must not cross a third-party notification boundary."""
    text = str(value or "").replace("\x00", "")
    text = _PRIVATE_KEY.sub(_LOCAL_ONLY, text)
    text = _CODE_FENCE.sub(_LOCAL_ONLY, text)
    text = _RAW_HTTP.sub(_LOCAL_ONLY, text)
    text = _REPORT_SECTION.sub(_LOCAL_ONLY, text)
    text = _COOKIE_LINE.sub(lambda match: match.group(1) + _REDACTED, text)
    text = _AUTH_VALUE.sub(lambda match: match.group(1) + " " + _REDACTED, text)
    text = _SECRET_ASSIGNMENT.sub(lambda match: match.group(1) + match.group(2) + _REDACTED, text)
    text = _WINDOWS_PATH.sub("[本地路径已隐藏]", text)
    text = _HOME_PATH.sub("[本地路径已隐藏]", text)
    text = _URL.sub(_sanitize_url, text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text[: max(1, int(limit))]


def sanitize_external_payload(value: Any) -> Any:
    """Recursively sanitize text values in an outbound card or webhook payload."""
    if isinstance(value, str):
        return sanitize_external_text(value)
    if isinstance(value, Mapping):
        result = {}
        for key, item in value.items():
            if isinstance(item, str) and _SENSITIVE_PAYLOAD_KEY.search(str(key)):
                result[key] = _LOCAL_ONLY
            else:
                result[key] = sanitize_external_payload(item)
        return result
    if isinstance(value, list):
        return [sanitize_external_payload(item) for item in value]
    if isinstance(value, tuple):
        return tuple(sanitize_external_payload(item) for item in value)
    return value


def outbound_audit_metadata(text: str, target: str = "") -> dict[str, Any]:
    """Return content-free audit metadata for one external notification."""
    encoded = text.encode("utf-8", errors="replace")
    return {
        "text_sha256": hashlib.sha256(encoded).hexdigest(),
        "text_bytes": len(encoded),
        "target_sha256": hashlib.sha256(str(target).encode("utf-8", errors="replace")).hexdigest(),
    }
