"""One admission decision for every request that may leave the process.

Why this module exists, in one paragraph: ``method`` cannot tell a read from a write.
``POST /search`` reveals routes; ``POST /logout`` and ``POST /api/items`` change state
with no body at all; ForgeRock's ``?action=validateGoto`` is a read that only answers
to POST. A rule as coarse as "GET/HEAD or nothing" under-serves the product, and a rule
as coarse as "POST is fine" is how a tool deletes someone's production data. So the
probe tier is **deny by default**: a non-read request goes out only when it can
*positively prove* it is a read, and everything unrecognised is refused.

The policy this module encodes is deliberately stricter than
``guardrails.guardrails.action_policy`` — it borrows that module's **classifier**
(``action_kind`` + ``value_scanners``), not its policy. ``refine`` is built around an
operator-proof workflow whose only relaxation lane needs an ``InertSurface`` allowlist
and a MAC-bound ledger, neither of which exists on this path; and its human gate
(``guardrails.tools.human_gate``) always answers
``hard_blocked:approval_authority_unconfigured``, so there is **no locally reachable
way to approve anything**. "Needs a human" therefore means "refused" here, and the
audit row says so.

Reason codes mirror the guardrails rule names on purpose, so the two layers do not
drift into two vocabularies for the same finding.

A second, independent scan covers **payloads on the read path**. Proving a bug
exists is in scope: boolean SQLi, a short ``SLEEP(5)``, ``id`` / ``whoami`` /
``echo`` / ``time``, LFI ``../../etc/passwd``, and SSRF that makes the *target* fetch
loopback / RFC1918 / cloud metadata over HTTP(S). DELETE / DROP / TRUNCATE /
dump / ``UPDATE … SET`` are the hard red line, even on GET. INSERT canaries
(test garbage) stay allowed except on ByteSRC. ``value_scanners.url_or_callback``
cannot do this job: it flags any URL-shaped value, so applying it to reads would
refuse ``GET /api/orders`` and ``GET ?url=https://internal.example/``. The
payload scan never looks at the request host — a local range at
``http://127.0.0.1:8080/api/orders`` stays an ordinary read.
"""
from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple
from urllib.parse import parse_qsl, unquote, urlsplit

from core.src_blackboard import read_operation_selector, state_changing_reason

# The read path. These never touch the scanner below — see ``admit``.
READ_METHODS = frozenset({"GET", "HEAD"})
# The probe tier: candidates for a non-mutating request. PUT/PATCH are here so that a
# refusal can name *why* (``update_semantics``) instead of shrugging ``method_not_allowed``.
PROBE_METHODS = frozenset({"OPTIONS", "POST", "PUT", "PATCH"})
#: Probe-tier methods that are *by their own semantics* an update, so no request carried
#: by them is ever admitted. Named separately from ``PROBE_METHODS`` because that set
#: answers "what may be declared" and this one answers "what may ever go out" — the
#: prompt and the console both need the second question, and neither should hardcode it.
UPDATE_METHODS = frozenset({"PUT", "PATCH"})
#: Every method this gate can, in principle, let through. The capability line the model
#: reads is built from this, so it can never advertise a verb the gate would refuse.
ADMISSIBLE_METHODS = (READ_METHODS | PROBE_METHODS) - UPDATE_METHODS
# Not in the vocabulary at all (``agents.surface_discovery._METHOD_ORDER``), and refused
# again here so the audit trail says which of the two happened.
DESTRUCTIVE_METHODS = frozenset({"DELETE"})

# Reason codes.
DESTRUCTIVE_METHOD = "destructive_method_forbidden"
NOT_PROVEN = "probe_not_proven_non_mutating"
CLASSIFIER_UNAVAILABLE = "admission_classifier_unavailable"
NOT_IN_PROBE_TIER = "method_not_in_probe_tier"
# Payload-level red lines (ByteSRC 测试红线 3/4/5, JSRC 测试规范, TPSA19-22).
# Prefix is stable so ``agents.src_agent.TERMINAL_REFUSAL_PREFIXES`` can match it.
HAZARDOUS_PAYLOAD = "hazardous_payload"
RESOURCE_EXHAUSTION = f"{HAZARDOUS_PAYLOAD}:resource_exhaustion"
DESTRUCTIVE_SQL = f"{HAZARDOUS_PAYLOAD}:destructive_sql"
SHELL_OR_WEBSHELL = f"{HAZARDOUS_PAYLOAD}:shell_or_webshell"
INTRANET_OR_METADATA = f"{HAZARDOUS_PAYLOAD}:intranet_or_metadata"
SYSTEM_COMMAND = f"{HAZARDOUS_PAYLOAD}:system_command"
DANGEROUS_SCHEME = f"{HAZARDOUS_PAYLOAD}:dangerous_scheme"

# ByteSRC《测试红线10条》+《安全报告处置规则 V6.0》：禁止执行系统命令、
# 禁止内网横向 / 打 metadata、禁止深层渗透。其它 SRC 仍走下面的存在性探针。
_BYTESRC_MARKERS = (
    "bytesrc", "bytedance", "src.bytedance.com",
    "字节跳动", "字节 src", "字节src",
)
# Bare ``id`` / ``time`` are ordinary query keys. Only command-injection shapes.
_BYTESRC_CMD_RE = re.compile(
    r"(?is)(?:(?:^|[=/\s;|&`$()]|\$\()(?:whoami|hostname|uname(?:\s+-a)?)\b"
    r"|(?:[=;|&`$()]|\$\()\s*(?:id|time)\b"
    r"|echo\s+[A-Za-z0-9._-]{1,40}"
    r"|\bsystem\s*\("
    r"|\.\./(?:\.\./)*(?:etc/(?:passwd|shadow)|windows/win\.ini|win\.ini))"
)

# Existence tests (boolean SQLi, SLEEP(5), WAITFOR DELAY '0:0:5') are allowed.
# BENCHMARK / long pipe waits are CPU/IO DoS, not "is there injection".
_RESOURCE_EXHAUSTION_RE = re.compile(
    r"(?is)(?:\bbenchmark\s*\(|\bdbms_pipe\s*\.\s*receive_message\b|\bget_lock\s*\()"
)
_SLEEP_SECONDS_RE = re.compile(
    r"(?is)\b(?:sleep|pg_sleep)\s*\(\s*(\d+(?:\.\d+)?)\s*\)"
)
_WAITFOR_RE = re.compile(
    r"(?is)waitfor\s+delay\s+'(\d+):(\d+):(\d+(?:\.\d+)?)'"
)
# One short delay is an existence probe. Anything longer is a stall.
_MAX_SLEEP_SECONDS = 5.0
# CRUD: query and INSERT canaries are allowed. DELETE / DROP / TRUNCATE / dump
# are the hard red line. UPDATE SET is treated as dangerous mutation.
_DESTRUCTIVE_SQL_RE = re.compile(
    r"(?is)(?:\bdrop\s+(?:table|database|index|view|schema)\b"
    r"|\btruncate\s+(?:table\b|\w+)"
    r"|\bdelete\s+from\b|\bupdate\s+\w+\s+set\b"
    r"|\binto\s+(?:out|dump)file\b|\bload_file\s*\(|\bxp_cmdshell\b)"
)
# ByteSRC 红线 5 still forbids 增删改, including INSERT canaries.
_BYTESRC_INSERT_RE = re.compile(r"(?is)\binsert\s+into\b")
# Post-exploitation only. Existence markers (id / whoami / echo / time /
# ../../etc/passwd) are allowed; reverse shells, webshells and shadow dumps are not.
_EXISTENCE_CMD = r"(?:id|whoami|hostname|uname(?:\s+-a)?|time|echo\s+[A-Za-z0-9._-]{1,40})"
_POST_EXPLOIT_RE = re.compile(
    r"(?is)(?:/bin/(?:ba)?sh\b|\bbash\s+-i\b|\bsh\s+-i\b"
    r"|\bcmd\.exe\b|\bpowershell(?:\.exe)?"
    r"|<\?php|\beval\s*\(|\bassert\s*\(|\bpassthru\s*\(|\bshell_exec\s*\("
    r"|\bproc_open\s*\("
    r"|/dev/tcp\b|\bmkfifo\b|\bnc\s+-e\b"
    r"|\bmeterpreter\b|\breverse[\s_-]?shell\b|\bwebshell\b"
    r"|cat\s+/etc/shadow|/etc/shadow"
    r"|\brm\s+-rf\b|\bcurl\s+[^\s]*\|\s*(?:ba)?sh\b)"
)
_SYSTEM_CALL_RE = re.compile(r"(?is)\bsystem\s*\(")
_EXISTENCE_SYSTEM_RE = re.compile(
    rf"(?is)\bsystem\s*\(\s*['\"]{_EXISTENCE_CMD}['\"]\s*\)"
)
_DANGEROUS_SCHEME_RE = re.compile(
    r"(?i)\b(?:gopher|dict|file|ldap|ldaps|jar|tftp)\s*:"
)
# Hosts extracted from *payloads* (query / body / path), never the request netloc.
_URL_HOST_RE = re.compile(
    r"(?i)(?:[a-z][a-z0-9+.-]*:)?//(?:\[([^\]]+)\]|([^/\s?#]+))"
)
_PATH_INTRANET_RE = re.compile(
    r"(?i)/(?:127(?:\.\d+){1,3}|10(?:\.\d+){3}|192\.168(?:\.\d+){2}"
    r"|172\.(?:1[6-9]|2\d|3[01])(?:\.\d+){2}|169\.254\.169\.254"
    r"|localhost)(?:[:/]|$)"
)
_METADATA_HOSTS = frozenset({
    "localhost", "ip6-localhost", "metadata.google.internal", "metadata.goog",
    "metadata.azure.com", "instance-data", "100.100.100.200",
    "169.254.169.254", "fd00:ec2::254", "::1", "0.0.0.0",
})
# Parameter names that mean "this value is a URL the server will fetch".
# Bare RFC1918 as ``?id=`` is left alone; as ``?url=`` it is intranet SSRF.
_URLISH_KEYS = frozenset({
    "url", "uri", "target", "dest", "destination", "redirect", "next", "continue",
    "callback", "webhook", "image", "img", "fetch", "proxy", "host", "domain",
    "returnurl", "return", "link", "src", "source", "endpoint", "site", "feed",
    "avatar", "imageurl", "fileurl", "targeturl", "notify_url", "notifyurl",
    "callback_url", "callbackurl", "redirect_uri", "redirecturi",
})

_GQL_PATH_TOKENS = ("graphql", "graphiql", "gql")
_GQL_ALLOWED_KEYS = frozenset({"query", "operationname", "variables"})
# Only a complete terminal route segment can prove a POST read. ``/search/delete``
# and ``/removeFromSearch`` are not reads merely because they contain "search".
_POST_READ_ROUTES = frozenset({"search", "_search", "query", "list", "lookup", "count"})
# These body fields select an RPC operation rather than supplying a search term.
# Unknown values refuse the route proof; an explicit read value is not, by itself,
# a new proof of a generic POST endpoint.
_BODY_OPERATION_KEYS = frozenset({
    "action", "_action", "op", "operation", "_operation", "do", "cmd",
    "method", "_method", "function", "func", "verb", "act", "task",
    "handler", "event", "method_name", "operationtype", "actiontype", "oper",
})
_BODY_AMBIGUOUS_ACTION_KEYS = frozenset({
    "type", "mode", "操作", "类型", "caozuo", "leixing",
})
_BODY_MUTATING_WORDS = (
    "delete", "remove", "destroy", "purge", "erase", "recycle", "clear", "drop",
    "trash", "wipe", "truncate", "unlink", "update", "edit", "modify", "patch",
    "reset", "cancel", "disable", "revoke", "logout", "signout", "unsubscribe",
    "refund", "transfer", "activate", "upload", "create", "register", "send",
    "删除", "移除", "销毁", "清空", "清除", "作废", "修改", "更新", "取消", "关闭",
)
_METHOD_OVERRIDE_KEYS = frozenset({
    "_method", "_method_override", "method_override", "x-http-method-override",
    "x-http-method", "x-original-method", "_verb",
})
# GraphQL only leaves the read operation off the wire when the document says
# ``mutation``/``subscription``; a word-boundary test is therefore sound for the
# operation *type*. (A server may still implement an effectful field as a query field —
# that is a broken server, and the budget + audit are the mitigation, not more regex.)
_GQL_NON_READ = re.compile(r"\b(mutation|subscription)\b", re.IGNORECASE)


@dataclass(frozen=True)
class Verdict:
    """Allowed, or refused with a reason the operator can act on."""

    allowed: bool
    reason: str = ""
    tier: str = "read"
    detail: Dict[str, Any] = field(default_factory=dict)


def _allow(tier: str, **detail: Any) -> Verdict:
    return Verdict(True, "", tier, detail)


def _refuse(reason: str, tier: str, **detail: Any) -> Verdict:
    return Verdict(False, reason, tier, detail)


# ---------------------------------------------------------------------------
# The semantic classifier (lazily imported, fail-closed)
# ---------------------------------------------------------------------------

_GUARDRAILS: Optional[Tuple[Any, Any, str]] = None


def _guardrails() -> Tuple[Any, Any, str]:
    """``(action_policy, value_scanners, error)`` — cached; error is ``""`` on success.

    Imported the same way ``notify/task_router.py`` does it: insert the package root on
    ``sys.path``. It is stdlib-only apart from the optional ``inert_surface`` bits we do
    not touch, so this adds no real dependency.
    """
    global _GUARDRAILS
    if _GUARDRAILS is None:
        try:
            root = Path(__file__).resolve().parents[1] / "guardrails-mcp"
            if str(root) not in sys.path:
                sys.path.insert(0, str(root))
            from guardrails import action_policy, value_scanners  # type: ignore

            _GUARDRAILS = (action_policy, value_scanners, "")
        except Exception as exc:  # noqa: BLE001 - an optional dependency
            _GUARDRAILS = (None, None, f"{type(exc).__name__}: {str(exc)[:120]}")
    return _GUARDRAILS


def classifier_available() -> bool:
    action_policy, value_scanners, _error = _guardrails()
    return action_policy is not None and value_scanners is not None


def classifier_error() -> str:
    return _guardrails()[2]


# ---------------------------------------------------------------------------
# The request card the classifier reads
# ---------------------------------------------------------------------------

def _parse_container(body: str, content_type: str) -> Optional[Any]:
    """The body as a mapping, or ``None`` when it is not one.

    Without this the classifier's body coverage is an illusion: ``action_kind`` walks
    *containers* and yields nothing for a ``str``, so ``action=delete`` sent as a form
    body would sail past the selector escalation. Parse before classifying.
    """
    text = (body or "").strip()
    if not text:
        return None
    lowered = (content_type or "").lower()
    form_shaped = "json" in lowered or text[:1] in ("{", "[")
    if form_shaped:
        try:
            parsed = json.loads(text, object_pairs_hook=_preserve_duplicate_json_keys)
        except (ValueError, TypeError):
            parsed = None
        if isinstance(parsed, (dict, list)):
            return parsed
    if "json" in lowered:
        return None
    if text[:1] in ("{", "["):
        return None
    try:
        pairs = parse_qsl(text, keep_blank_values=True)
    except ValueError:
        return None
    if not pairs:
        return None
    # Keep duplicate form keys. ``action=delete&action=query`` must not collapse
    # into only the last value before the semantic classifier sees it.
    values: Dict[str, Any] = {}
    for key, value in pairs:
        if key in values:
            previous = values[key]
            values[key] = previous + [value] if isinstance(previous, list) else [previous, value]
        else:
            values[key] = value
    return values


def _preserve_duplicate_json_keys(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    """Retain every JSON selector occurrence so a later benign key cannot mask it."""
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            previous = result[key]
            result[key] = previous + [value] if isinstance(previous, list) else [previous, value]
        else:
            result[key] = value
    return result


def build_action_card(method: str, url: str, body: str = "",
                      content_type: str = "") -> Dict[str, Any]:
    """The shape ``guardrails`` classifies. Contains no credentials by construction."""
    container = _parse_container(body, content_type)
    card: Dict[str, Any] = {"method": method, "url": url, "headers": {}}
    if body:
        card["body"] = body
    if isinstance(container, dict):
        card["form"] = container
    if isinstance(container, (dict, list)) and (
        "json" in (content_type or "").lower() or (body or "").strip()[:1] in ("{", "[")
    ):
        card["json"] = container
    return card


def _body_operation_reason(body: str, content_type: str) -> str:
    """Reject unproved RPC selectors, including nested/encoded and duplicate ones."""
    if not body:
        return ""
    container = _parse_container(body, content_type)
    if container is None:
        return ""
    for key, value in _body_fields(container):
        decoded_key = unquote(unquote(unquote(key))).strip().lower()
        # Rails/PHP-style brackets and dotted JSON field names can name the same
        # selector. Inspect every segment rather than only a literal "action" key.
        keys = {part for part in re.split(r"[.\[\]]+", decoded_key) if part}
        key_words = set(re.findall(r"[a-z]+", re.sub(
            r"(?<=[a-z0-9])(?=[A-Z])", " ", unquote(unquote(unquote(key))),
        ).lower()))
        if key_words.intersection(_BODY_MUTATING_WORDS) or keys & {"del", "rm"}:
            return "unknown_operation_selector"
        if keys & _METHOD_OVERRIDE_KEYS:
            return "unknown_operation_selector"
        decoded_value = unquote(unquote(unquote(str(value)))).strip().lower()
        if keys & _BODY_OPERATION_KEYS:
            if decoded_value not in {"get", "head", "options", "read", "list", "view", "search", "query"}:
                return "unknown_operation_selector"
        if keys & _BODY_AMBIGUOUS_ACTION_KEYS and (
            decoded_value in {"del", "rm"} or any(word in decoded_value for word in _BODY_MUTATING_WORDS)
        ):
            return "unknown_operation_selector"
    return ""


def _body_fields(value: Any) -> Iterable[Tuple[str, Any]]:
    """Include selector containers/nulls as well as scalar leaves; neither proves read."""
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key), child
            yield from _body_fields(child)
    elif isinstance(value, list):
        for child in value:
            yield from _body_fields(child)


# ---------------------------------------------------------------------------
# Payload red lines (GET as well as POST)
# ---------------------------------------------------------------------------

def _decode_layers(text: str) -> str:
    """Raw plus up to three rounds of percent-decode, so ``%53LEEP%28`` still matches."""
    current = text or ""
    layers = [current]
    for _ in range(3):
        nxt = unquote(current.replace("+", " "))
        if nxt == current:
            break
        layers.append(nxt)
        current = nxt
    return "\n".join(layers)


def _haystack(url: str, body: str) -> str:
    parsed = urlsplit(url or "")
    raw = "\n".join((parsed.path or "", parsed.query or "", parsed.fragment or "", body or ""))
    return _decode_layers(raw)


def _ipv4_from_host(host: str) -> Optional[Tuple[int, int, int, int]]:
    text = (host or "").strip().lower()
    if text.startswith("0x") and len(text) <= 10:
        try:
            number = int(text, 16)
        except ValueError:
            return None
        if 0 <= number < 2**32:
            return ((number >> 24) & 255, (number >> 16) & 255,
                    (number >> 8) & 255, number & 255)
        return None
    if text.isdigit():
        try:
            number = int(text, 10)
        except ValueError:
            return None
        if 0 <= number < 2**32:
            return ((number >> 24) & 255, (number >> 16) & 255,
                    (number >> 8) & 255, number & 255)
        return None
    parts = text.split(".")
    if len(parts) not in (2, 3, 4) or not all(parts):
        return None
    nums: List[int] = []
    for part in parts:
        try:
            if part.startswith("0") and part != "0" and set(part) <= set("01234567"):
                nums.append(int(part, 8))
            else:
                nums.append(int(part, 10))
        except ValueError:
            return None
    if any(item < 0 or item > 255 for item in nums):
        return None
    if len(nums) == 4:
        return (nums[0], nums[1], nums[2], nums[3])
    if nums[0] == 127 and len(nums) == 2:
        return (127, 0, 0, nums[1])
    if nums[0] == 127 and len(nums) == 3:
        return (127, nums[1], 0, nums[2])
    return None


def _is_forbidden_host(host: str) -> bool:
    """True for localhost / RFC1918 / link-local / cloud metadata — as a *host*."""
    text = (host or "").strip().lower().strip("[]")
    if not text:
        return False
    if "%" in text:
        text = text.split("%", 1)[0]
    if text.count(":") == 1 and not text.startswith(":"):
        left, right = text.rsplit(":", 1)
        if right.isdigit():
            text = left
    if text in _METADATA_HOSTS or text.endswith(".google.internal"):
        return True
    if text == "::1" or text.endswith("::1"):
        return True
    octets = _ipv4_from_host(text)
    if octets is None:
        return False
    a, b, _c, _d = octets
    if a in (0, 10, 127):
        return True
    if a == 192 and b == 168:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 169 and b == 254:
        return True
    return octets == (100, 100, 100, 200)


def _walk_values(obj: Any, key: str = "") -> Iterable[Tuple[str, str]]:
    if isinstance(obj, dict):
        for child_key, child in obj.items():
            yield from _walk_values(child, str(child_key))
    elif isinstance(obj, list):
        for item in obj:
            yield from _walk_values(item, key)
    elif obj is None:
        return
    else:
        yield key, str(obj)


def _payload_values(url: str, body: str) -> List[Tuple[str, str]]:
    parsed = urlsplit(url or "")
    values: List[Tuple[str, str]] = []
    try:
        values.extend(parse_qsl(parsed.query, keep_blank_values=True))
    except ValueError:
        pass
    container = _parse_container(body, "")
    if container is not None:
        values.extend(_walk_values(container))
    elif body:
        values.append(("", body))
        try:
            values.extend(parse_qsl(body, keep_blank_values=True))
        except ValueError:
            pass
    return values


def _host_in_blob(blob: str) -> bool:
    if _PATH_INTRANET_RE.search(blob):
        return True
    for match in _URL_HOST_RE.finditer(blob):
        host = match.group(1) or match.group(2) or ""
        if _is_forbidden_host(host):
            return True
    return False


def _overlong_delay(blob: str) -> bool:
    """True when a delay payload would stall the target longer than an existence probe."""
    for match in _SLEEP_SECONDS_RE.finditer(blob):
        try:
            if float(match.group(1)) > _MAX_SLEEP_SECONDS:
                return True
        except ValueError:
            return True
    for match in _WAITFOR_RE.finditer(blob):
        try:
            hours, minutes, seconds = (float(match.group(1)), float(match.group(2)),
                                       float(match.group(3)))
        except ValueError:
            return True
        if hours * 3600 + minutes * 60 + seconds > _MAX_SLEEP_SECONDS:
            return True
    return False


def _is_post_exploit_shell(blob: str) -> bool:
    """True for reverse shells / webshells / shadow dumps, not ``id``/``whoami``."""
    if _POST_EXPLOIT_RE.search(blob):
        return True
    if _SYSTEM_CALL_RE.search(blob) and not _EXISTENCE_SYSTEM_RE.search(blob):
        return True
    return False


def is_bytesrc_program(program: str = "", authorization: str = "") -> bool:
    """True when this engagement is ByteSRC (V6 / 测试红线 10 条)."""
    blob = f"{program}\n{authorization}".lower()
    return any(marker.lower() in blob for marker in _BYTESRC_MARKERS)


def _bytesrc_probe_reason(blob: str) -> str:
    """ByteSRC overlay: no system commands, no LFI of host files, no intranet SSRF."""
    if _BYTESRC_CMD_RE.search(blob) or _EXISTENCE_SYSTEM_RE.search(blob):
        return SYSTEM_COMMAND
    if _BYTESRC_INSERT_RE.search(blob):
        return DESTRUCTIVE_SQL
    if _host_in_blob(blob):
        return INTRANET_OR_METADATA
    return ""


def hazardous_payload_reason(
    url: str,
    body: str = "",
    *,
    program: str = "",
    authorization: str = "",
) -> str:
    """Why this request is a banned high-risk payload, or ``""``.

    Looks at path / query / body, never the request host. Proving a bug exists
    is in scope: boolean SQLi, a short ``SLEEP(5)`` / ``WAITFOR DELAY``,
    command-injection markers (``id`` / ``whoami`` / ``echo`` / ``time``), LFI
    ``../../etc/passwd``, and HTTP(S) SSRF to loopback / RFC1918 / cloud
    metadata. DELETE / DROP / TRUNCATE / dump / LOAD_FILE / ``UPDATE … SET``
    are the hard red line. INSERT canaries are allowed except on ByteSRC.
    Exhausting the target (BENCHMARK, SLEEP longer than 5s), reverse shells /
    webshells, and ``gopher``/``dict``/``file``/``ldap`` are not.

    ByteSRC engagements (``program`` / ``authorization`` matching 字节) additionally
    refuse system-command probes, ``/etc/passwd`` LFI, and HTTP(S) SSRF to
    loopback / RFC1918 / cloud metadata — 红线 2 / 5, 不要做危险测试.
    """
    blob = _haystack(url, body)
    if _DANGEROUS_SCHEME_RE.search(blob):
        return DANGEROUS_SCHEME
    if _RESOURCE_EXHAUSTION_RE.search(blob) or _overlong_delay(blob):
        return RESOURCE_EXHAUSTION
    if _DESTRUCTIVE_SQL_RE.search(blob):
        return DESTRUCTIVE_SQL
    if _is_post_exploit_shell(blob):
        return SHELL_OR_WEBSHELL
    if is_bytesrc_program(program, authorization):
        extra = _bytesrc_probe_reason(blob)
        if extra:
            return extra
    return ""


# ---------------------------------------------------------------------------
# The decision
# ---------------------------------------------------------------------------

def admit(
    *,
    method: str,
    url: str,
    body: str = "",
    content_type: str = "",
    program: str = "",
    authorization: str = "",
) -> Verdict:
    """Allowed, or refused with a reason. Pure; no network, no I/O.

    Gate order is the point, and the caller runs this *after* the scope check, the
    method-declaration check and the body-declaration check, so this function is the
    fifth gate and the last one before the request budget.
    """
    verb = str(method or "GET").strip().upper() or "GET"

    if verb in DESTRUCTIVE_METHODS:
        # Checked before anything else so the audit names the real reason rather than
        # a generic "method not allowed". Defence in depth: DELETE is also absent from
        # the declaration vocabulary, so a document cannot ask for it either.
        return _refuse(DESTRUCTIVE_METHOD, "read", method=verb)

    if verb in READ_METHODS:
        return _admit_read(verb, url, body, program=program, authorization=authorization)

    tier = "probe"
    if verb not in PROBE_METHODS:
        return _refuse(NOT_IN_PROBE_TIER, tier, method=verb)

    # Guards first. ``state_changing_reason`` runs before the word list, so
    # ``?_method=DELETE`` lands in the selector branch rather than being read as
    # "the URL mentions delete". No declaration buys past either of these.
    read_reason = state_changing_reason(url)
    if read_reason == "unknown_operation_selector":
        return _refuse("unknown_operation_selector", tier, method=verb)
    if read_reason:
        return _refuse("state_changing_endpoint", tier, method=verb)

    # Payload red lines do not need the classifier, so they run even when it is
    # missing. A proven GraphQL ``query`` that embeds DELETE/BENCHMARK is still refused.
    hazard = hazardous_payload_reason(
        url, body, program=program, authorization=authorization)
    if hazard:
        return _refuse(hazard, tier, method=verb)

    action_policy, value_scanners, error = _guardrails()
    if action_policy is None or value_scanners is None:
        # Fail closed: the widening is unavailable, the read path is untouched, and the
        # run is not aborted. Never fail open here.
        return _refuse(CLASSIFIER_UNAVAILABLE, tier, method=verb, error=error)

    card = build_action_card(verb, url, body, content_type)
    try:
        kind = action_policy.action_kind(card)
        scan = value_scanners.scan(card)
    except Exception as exc:  # noqa: BLE001 - a broken classifier must not open the gate
        return _refuse(CLASSIFIER_UNAVAILABLE, tier, method=verb,
                       error=f"{type(exc).__name__}: {str(exc)[:120]}")

    if kind == "delete":
        return _refuse("mutating_request_refused:delete", tier, method=verb, kind=kind)
    if kind == "modify":
        return _refuse("mutating_request_refused:update_semantics", tier, method=verb, kind=kind)
    # HTTP(S) URL-valued parameters are SSRF existence probes (metadata / loopback /
    # callback). ``gopher``/``dict``/``file`` already failed above via
    # ``hazardous_payload_reason``. Do not refuse ``url_or_callback`` here.

    # Now the request has to *prove* it is a read. Note what is deliberately NOT checked
    # above: ``privilege_or_credential`` / ``cleanup_keyword`` / ``shared_state``.
    #
    # Those three answer "would *changing* this be dangerous?" — they trip on the URL's
    # shape, not on our request's effect. ``_PRIV_ENDPOINT_RE`` matches ``/users?``, so
    # any user-admin endpoint trips it; ``_SHARED_HINTS`` contains ``config`` / ``group`` /
    # ``role``; ``_CLEANUP_HINTS`` contains ``order`` / ``notify``. Applying them to reads
    # refuses ``OPTIONS /openidm/config/managed`` (RFC-safe, zero side effects) and
    # ``POST /openidm/managed/user?_action=validateGoto`` — measured on a real target
    # 2026-09-21, which is how this ordering was found. Reading a sensitive surface is the
    # hunt's whole job; ``guardrails.action_policy.refine`` only consults these scanners
    # for create/modify/other for exactly this reason.
    body_reason = _body_operation_reason(body, content_type)
    if body_reason:
        return _refuse(body_reason, tier, method=verb, kind=kind)
    proof = _read_proof(verb, url, body, content_type)
    if proof:
        return _allow(tier, method=verb, proof=proof)

    # Not proven. The remaining signals now only choose which reason to show the model,
    # so the refusal is actionable instead of a shrug.
    for signal, label in (("privilege_or_credential", "privilege_or_credential"),
                          ("cleanup_keyword", "irreversible_surface"),
                          ("shared_state", "shared_state")):
        if scan.get(signal):
            return _refuse(f"{NOT_PROVEN}:{label}", tier, method=verb, kind=kind)
    return _refuse(NOT_PROVEN, tier, method=verb, kind=kind)


def _read_proof(verb: str, url: str, body: str, content_type: str = "") -> str:
    """``"options"`` / ``"read_selector"`` / ``"graphql_query"`` / ``"read_route"``.

    Four shapes and nothing else, each of which says on its face what it does:
    ``OPTIONS`` cannot mutate by spec; a read operation selector is the endpoint
    declaring its own operation; a GraphQL ``query`` needs the literal keyword
    ``mutation`` to be anything else. An empty body is **not** on this list — ``POST
    /logout`` and ``POST /api/items`` both mutate without one.
    """
    if verb == "OPTIONS":
        return "" if body else "options"
    if verb == "POST":
        if not _inspectable_post_body(body, content_type):
            return ""
        if read_operation_selector(url):
            return "read_selector"
        if _graphql_read(url, body):
            return "graphql_query"
        if _post_read_route(url):
            return "read_route"
    return ""


def _post_read_route(url: str) -> bool:
    """Only a complete terminal route segment can identify a POST read endpoint."""
    path = urlsplit(url or "").path.rstrip("/")
    for _ in range(3):
        decoded = unquote(path)
        if decoded == path:
            break
        path = decoded
    segment = path.rsplit("/", 1)[-1].lower()
    return segment in _POST_READ_ROUTES


def _inspectable_post_body(body: str, content_type: str) -> bool:
    """Body formats whose operation selectors can be checked before sending."""
    if not body:
        return True
    media_type = (content_type or "").split(";", 1)[0].strip().lower()
    if media_type and not (
        media_type == "application/json" or media_type.endswith("+json")
        or media_type == "application/x-www-form-urlencoded"
    ):
        return False
    if not body.lstrip().startswith(("{", "[")):
        try:
            # parse_qsl's permissive default accepts arbitrary text as an empty
            # form key. That cannot count as an inspected search/filter body.
            parse_qsl(body, keep_blank_values=True, strict_parsing=True)
        except ValueError:
            return False
    container = _parse_container(body, content_type)
    # Opaque payloads and JSON batches cannot prove every operation is a read.
    return isinstance(container, dict)


def _admit_read(
    verb: str,
    url: str,
    body: str = "",
    *,
    program: str = "",
    authorization: str = "",
) -> Verdict:
    """The read path.

    Deliberately *not* routed through ``value_scanners``: it flags any parameter whose
    value looks like a URL (``?url=https://…``) as server-side egress, and any mention
    of ``config``/``settings``/``order`` as shared state — which is to say it refuses
    ``GET /api/orders``, the product's single most common read. The token-set heuristic
    below is weaker on purpose; that is the right trade for reads.

    Two tightenings over a naive GET-allow: a state-changing-looking URL is refused
    **unconditionally**, and a payload that deletes, dumps, or ``UPDATE … SET``
    (DROP/DELETE/TRUNCATE/outfile, gopher, reverse shell, webshell, BENCHMARK) is
    refused even though the verb is a read. INSERT canaries are allowed except on
    ByteSRC. Short ``SLEEP(5)``, ``id``/``whoami``/``echo``/``time``, LFI
    ``../../etc/passwd``, and HTTP(S) SSRF to metadata / loopback / RFC1918 to prove
    a bug exists are allowed. ``value_scanners`` still stays off this path so
    ``GET ?url=https://internal.example/`` and ``GET /api/orders`` remain the
    product's core reads.
    """
    reason = state_changing_reason(url)
    if reason == "unknown_operation_selector":
        return _refuse("unknown_operation_selector", "read", method=verb)
    if reason:
        return _refuse("state_changing_endpoint", "read", method=verb)
    hazard = hazardous_payload_reason(
        url, body, program=program, authorization=authorization)
    if hazard:
        return _refuse(hazard, "read", method=verb)
    # Payload red lines take precedence over selector heuristics: a destructive
    # SQL body should be audited as destructive SQL, even when its free-form text
    # happens to contain a word such as ``delete``.
    body_reason = _body_operation_reason(body, "")
    if body_reason:
        return _refuse(body_reason, "read", method=verb)
    return _allow("read", method=verb)


def _graphql_read(url: str, body: str) -> bool:
    """A GraphQL *query*, proven from the wire shape. All conditions must hold."""
    lowered = str(url or "").lower()
    if not any(token in lowered for token in _GQL_PATH_TOKENS):
        return False
    try:
        parsed = json.loads(body or "")
    except (ValueError, TypeError):
        return False
    if not isinstance(parsed, dict):
        return False
    keys = {str(key).lower() for key in parsed}
    if "query" not in keys or not keys <= _GQL_ALLOWED_KEYS:
        return False
    return _GQL_NON_READ.search(json.dumps(parsed, ensure_ascii=False)) is None


__all__ = [
    "CLASSIFIER_UNAVAILABLE", "DANGEROUS_SCHEME", "DESTRUCTIVE_METHOD",
    "DESTRUCTIVE_METHODS", "DESTRUCTIVE_SQL", "HAZARDOUS_PAYLOAD",
    "INTRANET_OR_METADATA", "NOT_IN_PROBE_TIER", "NOT_PROVEN", "PROBE_METHODS",
    "READ_METHODS", "RESOURCE_EXHAUSTION", "SHELL_OR_WEBSHELL", "SYSTEM_COMMAND",
    "Verdict",
    "admit", "build_action_card", "classifier_available", "classifier_error",
    "hazardous_payload_reason", "is_bytesrc_program",
]
