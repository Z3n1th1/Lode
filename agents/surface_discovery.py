"""Scope-bound passive HTML/JS surface discovery for authorized SRC work.

This module is intentionally separate from ``intel``.  It performs a small,
sequential set of GET requests against one explicitly authorized target and
extracts routes, API hints, manifests, OpenAPI paths, GraphQL markers, and
source-map references.  It never submits forms, mutates state, or invokes an
LLM/scanner.
"""

from __future__ import annotations

import ipaddress
import json
import re
import secrets
import ssl
import time
from difflib import SequenceMatcher
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
import zlib
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from core.action_admission import ADMISSIBLE_METHODS as _ADMISSIBLE_METHODS
from core.rate_limit import limiter_for
from core.src_blackboard import state_changing_reason


API_PREFIXES = {
    "api", "apis", "openapi", "v1", "v2", "v3", "rest", "rpc", "graphql",
    "gateway", "service", "auth", "oauth", "sso", "user", "users", "admin",
    "system", "config", "upload", "download", "export", "file", "order",
    "orders", "payment", "pay", "message", "notify", "data", "report",
    "search", "query", "list", "detail", "info", "profile", "manage",
    "console", "monitor", "internal", "debug", "health", "status", "version",
    # Resource nouns the list only had half of. `orders` was here and `products` was
    # not, so a bundle that built its URL by concatenation lost the endpoint entirely:
    # `API_BASE + "/products?q="` leaves a bare fragment, `_looks_high_signal` rejects
    # it, and the candidate never exists. Measured 2026-09-25 on ranges/lode-range,
    # where that took SQLi recall from 4/5 to 0/9 before the fixture was corrected.
    #
    # Adding words fixes instances, not the class — any hand-written noun list is
    # incomplete by construction, and this is the third such list to lose something
    # real today. Kept deliberately short for that reason: every entry widens candidate
    # generation, and candidates are what the request budget is spent on.
    "product", "products", "item", "items", "cart", "catalog",
    "category", "categories", "post", "posts", "comment", "comments",
    "article", "articles", "tag", "tags",
}
DISCOVERY_RE = re.compile(
    r"(?:^|/)(?:swagger|api-docs|openapi|graphql|graphiql|actuator|healthz?|"
    r"readyz?|livez?|status|version|metrics|info|config|schema)(?:/|$|[.?_-])",
    re.I,
)
# Exposure, not API surface: paths that matter because they *leak* something, not
# because they route somewhere. Deliberately a second dimension rather than more
# entries in API_PREFIXES — the two answer different questions and get tuned apart.
#
# Why it exists: robots.txt is the one place a site volunteers where its own
# secrets live (`Disallow: /.git`, `Disallow: /backup`). Those lines were always
# parsed, but `_looks_high_signal` kept only API-shaped paths, so they were dropped
# silently — measured 2026-09-25 on ranges/lode-range, where three planted bugs
# (`/.git/config`, `/.env`, `/backup/users.sql`) never became candidates while the
# knowledge base already shipped an `insecure-scm-test` module about exactly this.
EXPOSURE_RE = re.compile(
    r"(?:^|/)(?:\.git|\.svn|\.hg|\.env|\.aws|\.ssh|\.htpasswd|\.htaccess"
    r"|id_rsa|id_dsa|credentials|secrets?|passwd|shadow|phpinfo|server-status"
    r"|wp-config|web\.config|config\.php|backup|backups|dump|dumps|db|database"
    r"|archive|archives|private|old|tmp|temp)(?:$|[/.?_-])"
    r"|\.(?:sql|bak|old|orig|save|swp|swo|dump|sqlite3?|tar|tgz|7z|rar|pem|p12|pfx|jks)(?:$|[?#])",
    re.I,
)
STATIC_RE = re.compile(r"\.(?:js|mjs|css|map|json|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|pdf|zip)(?:[?#].*)?$", re.I)
SKIP_RE = re.compile(r"^/(?:static|assets|public|dist|build|node_modules|vendor|img|images|css|fonts)/", re.I)
PATH_VAR_RE = re.compile(r"[:*{}()[\]<>]|(?:\$\{)")
URL_RE = re.compile(r"https?://[^\s\"'<>`]+", re.I)
QUOTED_PATH_RE = re.compile(r"[\"'`]((?:/|\./|\.\./)[A-Za-z0-9._~!$&'()*+,;=:@/%?-]{2,240})[\"'`]", re.I)
FIELD_RE = re.compile(
    r"(?:(?:url|path|api|endpoint|route|requestUrl|baseURL|baseUrl)\s*[:=]\s*|"
    r"(?:fetch|axios|request|\$http|ajax|get|post|put|delete|patch)\s*\(\s*)"
    r"[\"']([^\"']{2,240})[\"']",
    re.I,
)
ROUTER_RE = re.compile(r"(?:path|redirect)\s*:\s*[\"'](/[^\"']{1,240})[\"']", re.I)
SOURCE_MAP_RE = re.compile(r"//#\s*sourceMappingURL=([^\s]+)")
CHUNK_RE = re.compile(r"[\"']([^\"']+\.(?:js|mjs|map)(?:\?[^\"']*)?)[\"']", re.I)

# Probes sent to every target, in two named groups so the spend is legible.
#
# Both groups draw on the SAME run budget as the agent loop — the total is a promise
# to the program (docs/security-boundary.md) — so "make room for the exposure probes"
# cannot mean exempting them from the cap. It means not spending requests on
# near-duplicate framework paths. Measured 2026-09-25 on ranges/lode-range: adding
# three exposure probes displaced three agent requests and cost a cycle, because the
# list carried six manifest/swagger variants that only ever answer on the one
# framework that names them. One representative per family is kept.
EXPOSURE_PATHS = (
    # `/.env` belongs here rather than in extraction because nothing on a page ever
    # *links* to it — there is no signal to find, only a path to try.
    "/.env", "/.git/config", "/backup/",
)
FRAMEWORK_PATHS = (
    "/asset-manifest.json", "/manifest.json",
    "/swagger.json", "/swagger-ui.html", "/v3/api-docs", "/openapi.json",
    "/graphql",
    "/actuator/health", "/druid", "/nacos", "/api/workflow/search",
)
# Order is budget priority: a tight budget truncates the tail, so highest yield
# first — exposure, then robots/sitemap (the crawl's main source of paths), then the
# framework sweep. High-risk management/orchestration probes replaced near-duplicate
# swagger/openapi variants (api-docs, v2/api-docs, openapi.yaml) so the per-target
# tax stays ≤16 while Origin-Direct / RCE surfaces get a first look.
# Dropped on purpose: /static/js/manifest.json, /webpack-manifest.json
# and /build/asset-manifest.json, /swagger/v{1,2}/swagger.json, /graphiql,
# /api-docs, /api-docs.json, /v2/api-docs, /openapi.yaml.
SEED_PATHS = EXPOSURE_PATHS + ("/robots.txt", "/sitemap.xml") + FRAMEWORK_PATHS


def _host(value: str) -> str:
    return str(value or "").strip().lower().strip("[]").rstrip(".")


_SENSITIVE_QUERY_KEYS = frozenset({
    "code", "token", "access_token", "refresh_token", "id_token", "nonce",
    "state", "secret", "client_secret", "password", "session", "cookie",
    "authorization",
})


def _safe_logged_url(value: str) -> str:
    """Keep evidence useful while removing bearer-like query values."""
    raw = str(value or "")
    parsed = urlsplit(raw)
    if not parsed.query:
        return raw
    pairs = []
    for key, item in parse_qsl(parsed.query, keep_blank_values=True):
        pairs.append((key, "[redacted]" if key.lower() in _SENSITIVE_QUERY_KEYS else item))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(pairs), ""))


def _as_tuple(value: Any) -> tuple:
    """A string is one value, not a sequence of characters.

    ``for item in (data.get("allowed_domains") or ())`` iterates a *string*
    character by character, so a scope file that wrote ``"allowed_methods": "POST"``
    silently became ``P``, ``O``, ``S``, ``T`` — four unknowns that fail open in the
    only place that matters. Hand-written scope files are exactly where this happens.
    """
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple, set, frozenset)):
        return tuple(value)
    return ()


def _path_prefix_tuple(value: Any) -> tuple[str, ...]:
    """Normalize path prefixes without turning a string into characters."""
    values = _as_tuple(value)
    prefixes: list[str] = []
    for item in values:
        raw = str(item or "").strip()
        if not raw:
            continue
        if "://" in raw:
            raw = urlsplit(raw).path or "/"
        if not raw.startswith("/"):
            raw = "/" + raw
        raw = "/" + "/".join(part for part in raw.split("/") if part)
        prefixes.append(raw if raw == "/" else raw.rstrip("/"))
    return tuple(dict.fromkeys(prefixes))


def _path_rules(value: Any) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Read host-specific path prefixes from a scope document.

    A host allow-list without path rules remains backward compatible.  When a
    host is present in this map, only the listed path prefixes are eligible;
    this keeps a broad platform host from being mistaken for authorization to
    probe unrelated tenants or management surfaces.
    """
    if not isinstance(value, Mapping):
        return ()
    rules: list[tuple[str, tuple[str, ...]]] = []
    for host, prefixes in value.items():
        key = str(host or "").strip().lower()
        if not key:
            continue
        normalized = _path_prefix_tuple(prefixes)
        if normalized:
            rules.append((key, normalized))
    return tuple(rules)


def _path_prefix_matches(path: str, prefix: str) -> bool:
    path = "/" + "/".join(part for part in str(path or "/").split("/") if part)
    prefix = "/" + "/".join(part for part in str(prefix or "/").split("/") if part)
    if prefix == "/":
        return True
    return path == prefix or path.startswith(prefix + "/")


# 方法词表与顺序都是固定的:两份声明了同一个集合的 scope 必须写出同一个 tuple,
# 否则它们的桶/缓存/比较都会因为书写顺序不同而不同。
#
# DELETE 不在这里。它不是"没授权所以拿不到",而是**不是合法取值** —— 一份写着 DELETE
# 的文档读进来的结果和不写它一样(见 `_method_tuple` 的过滤),而任何实发的 DELETE 都由
# `core.action_admission` 以 destructive_method_forbidden 拒掉。平台红线写的是"禁止任何
# 增删改数据/配置的写操作",删除是里面最不可逆的那一个,不该留在一个"声明一下就能用"的词表里。
_METHOD_ORDER = ("GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH")
_METHOD_VOCABULARY = frozenset(_METHOD_ORDER)
# 只读是底线,不是默认值:声明什么都拿不掉这两个。
_SAFE_METHODS = ("GET", "HEAD")
# 闸门**实际会发**的方法,从闸门自己那里取(`core.action_admission.ADMISSIBLE_METHODS`),
# 不在这儿另写一份 —— 提示词里那句"允许的方法"必须和沙箱会执行的动作是同一件事,
# 否则模型要么从不尝试它其实能做的,要么写出一份到闸门就死的计划。


def _method_tuple(value: Any) -> tuple[str, ...]:
    """Upper-cased, de-duplicated, filtered to the vocabulary.  GET/HEAD always in.

    An empty, missing or garbage declaration means *read-only*, not "everything" and
    not "nothing": fail-closed here is "you may still look", which keeps a scope file
    that predates this field working exactly as it did.
    """
    declared = {str(item).strip().upper() for item in _as_tuple(value) if str(item).strip()}
    allowed = (declared & _METHOD_VOCABULARY) | set(_SAFE_METHODS)
    return tuple(method for method in _METHOD_ORDER if method in allowed)


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


# req/s 是程序自己用的单位("所有流量 <= 3 req/s"),delay 是我们换算出来的。让操作员
# 手算 1/3 是在制造错误来源。间隔的上下界只写一次:req/s 和 delay 是同一种东西的两种
# 拼法,写错时该撞的是同一堵墙。
MIN_DELAY_SECONDS = 0.1
MAX_DELAY_SECONDS = 30.0


def _delay_from_rate(value: Any) -> float | None:
    """``requests_per_second`` → ``delay_seconds``, or ``None`` if unparseable.

    两种拼法共用同一组上下界,所以写错哪一个撞的都是同一堵墙,不会出现"换个写法就
    能打得更快"。上界(``MAX_DELAY_SECONDS``,30s)是既有的节奏界,不是这次新加的:
    比它更慢的声明会被夹到 30s,``min_interval_seconds`` 一直如此。读不懂(``"fast"``)
    或明显是 0 的一律返回 ``None``,让调用方退回它自己的读法,而不是替程序猜速率。
    """
    try:
        rate = float(value)
    except (TypeError, ValueError):
        return None
    if rate <= 0:
        return None
    return max(MIN_DELAY_SECONDS, min(1.0 / rate, MAX_DELAY_SECONDS))


def _readonly_url_reason(value: str) -> str:
    """Additional GET safety check, not proof of a server's implementation.

    The word list moved to ``core.src_blackboard.state_changing_reason`` when the
    blackboard and the agent gate needed the same answer — three copies of "what
    counts as state-changing" would drift apart, and the gate is the one that has to
    be right. The name stays because it is imported by ``agents/src_agent.py``.
    """
    if _is_safe_auth_navigation(value):
        return ""
    return state_changing_reason(value)


def _is_safe_auth_navigation(value: str) -> bool:
    """Allow only the read-only OAuth login hops needed to reach an in-scope app.

    OAuth authorization URLs often carry words such as ``create`` and ``manage``
    in the requested permission string.  Those words describe the consent being
    requested after login, not a mutation performed by this GET navigation.
    The narrow host/path/parameter check prevents this exception from becoming a
    general bypass for state-changing URLs.
    """
    parsed = urlsplit(str(value or ""))
    if _host(parsed.hostname or "") != "accounts.shopify.com":
        return False
    path = parsed.path.rstrip("/").lower()
    if path == "/oauth/authorize":
        query = parse_qs(parsed.query, keep_blank_values=True)
        return (query.get("response_type", [""])[0].lower() == "code"
                and bool(query.get("redirect_uri", [""])[0]))
    return False


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _scope_host(value: str) -> str:
    parsed = urlsplit(str(value or ""))
    item = parsed.hostname or str(value or "")
    return _host(item)


def _host_matches(host: str, entry: str, *, descendants: bool = True) -> bool:
    host = _host(host)
    entry = _scope_host(entry)
    wildcard = entry.startswith("*.")
    if wildcard:
        entry = entry[2:]
    if not host or not entry:
        return False
    if host == entry:
        return not wildcard or descendants
    return descendants and host.endswith("." + entry)


@dataclass(frozen=True)
class SurfaceScope:
    program: str
    authorization: str
    # 预算身份 —— 一次 engagement 一个令牌桶(见 core/rate_limit)。
    #
    # 它和 ``program`` 是两件事:``program`` 是给人看的名字,控制台上每个 job 都铸
    # 一个新的(``console-<run_id>``),拿它当桶的键就等于一个 job 一个桶。一次粘贴
    # 20 个目标 = 20 个桶 = 程序写明的 3 req/s 变成 16。
    #
    # 所以 Console 路径显式声明 ``turn-<turn_id>``(一次对话 = 一次 engagement),
    # 而 scope 文件不声明 —— 空值回落到 ``program``,CLI 的行为一个字都不变。
    engagement: str = ""
    allowed_domains: tuple[str, ...] = ()
    allowed_hosts: tuple[str, ...] = ()
    allowed_ips: tuple[str, ...] = ()
    # Optional host -> path-prefix restrictions.  Empty preserves the legacy
    # host-only scope behavior; a configured host is path-scoped fail-closed.
    allowed_path_prefixes: tuple[tuple[str, tuple[str, ...]], ...] = ()
    forbidden: tuple[str, ...] = ()
    # 能力维度:这份授权文档允许**做什么**,不只是允许**去哪里**。
    #
    # 以前只读是 agents/src_agent.py 里一个硬编码的 {"GET","HEAD"},所以授权文档从
    # 来没有说过"这个 worker 可以做什么" —— 想放宽就只能在代码里放宽,那是把治理
    # 从句面搬进源码。默认仍然只有 GET/HEAD,而且是恒并集:声明什么都拿不掉。
    allowed_methods: tuple[str, ...] = _SAFE_METHODS
    # 允许带请求体。单独一个开关,因为"可以发 POST"和"可以发任意 body"是两件事。
    allow_request_body: bool = False
    # 只改变 scope 内候选的排序，绝不扩大主机/方法/请求范围。
    # 默认遵循操作员方向：优先严重/高危/RCE 形状。
    priority_objectives: tuple[str, ...] = ("critical", "high", "rce")
    timeout_seconds: float = 8.0
    delay_seconds: float = 0.4

    def __post_init__(self) -> None:
        # 归一化放在类型上,不只放在 from_mapping 里:直接构造 SurfaceScope 的调用方
        # 同样不该拿到一份"GET/HEAD 被声明掉"的授权。幂等,所以两种路径的结果一致。
        object.__setattr__(self, "allowed_methods", _method_tuple(self.allowed_methods))
        normalized_rules: list[tuple[str, tuple[str, ...]]] = []
        raw_rules = (_path_rules(self.allowed_path_prefixes)
                     if isinstance(self.allowed_path_prefixes, Mapping)
                     else self.allowed_path_prefixes)
        for item in raw_rules:
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                continue
            host, prefixes = item
            key = str(host or "").strip().lower()
            values = _path_prefix_tuple(prefixes)
            if key and values:
                normalized_rules.append((key, values))
        object.__setattr__(self, "allowed_path_prefixes", tuple(normalized_rules))
        allowed_priorities = {"critical", "high", "rce", "orphan_origin", "management"}
        priorities = tuple(dict.fromkeys(
            str(item).strip().lower() for item in self.priority_objectives
            if str(item).strip().lower() in allowed_priorities
        ))
        object.__setattr__(self, "priority_objectives", priorities)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "SurfaceScope":
        nested = value.get("scope")
        data = nested if isinstance(nested, Mapping) else value
        domains = tuple(str(item).strip() for item in _as_tuple(data.get("allowed_domains")) if str(item).strip())
        hosts = tuple(str(item).strip() for item in _as_tuple(data.get("allowed_hosts") or data.get("hosts")) if str(item).strip())
        forbidden = tuple(str(item).strip() for item in _as_tuple(data.get("forbidden") or data.get("forbidden_hosts")) if str(item).strip())
        rate = data.get("rate_limit") if isinstance(data.get("rate_limit"), Mapping) else {}
        timeout = value.get("timeout_seconds", rate.get("timeout_seconds", 8))
        # req/s 优先,而且和 delay 互斥:程序里写的是 req/s,换算是我们的事。两个都给
        # 就按 req/s 走 —— 让 1/3 和 0.333 这种手算结果互相打架没有意义。
        raw_rate = data.get("requests_per_second", value.get("requests_per_second"))
        if raw_rate is None:
            raw_rate = rate.get("requests_per_second")
        from_rate = _delay_from_rate(raw_rate) if raw_rate is not None else None
        if from_rate is not None:
            delay = from_rate
        else:
            delay = value.get("surface_delay_seconds", rate.get("surface_delay_seconds", rate.get("min_interval_seconds", 0.4)))
        try:
            timeout = max(1.0, min(float(timeout), 60.0))
        except (TypeError, ValueError):
            timeout = 8.0
        try:
            delay = max(0.1, min(float(delay), 30.0))
        except (TypeError, ValueError):
            delay = 0.4
        authorization = str(value.get("authorization") or data.get("authorization") or "").strip()
        if not authorization and value.get("schema") == "TargetCard/v1":
            authorization = "confirmed_target_card:" + str(value.get("target_id") or "unknown")
        program = str(value.get("program") or value.get("name") or "authorized-program").strip()
        # 文件里没写 engagement 就是 CLI 那条路:回落 program,桶的键和以前逐字相同。
        engagement = str(data.get("engagement") or value.get("engagement") or "").strip() or program
        return cls(
            program=program,
            authorization=authorization,
            engagement=engagement,
            allowed_domains=domains,
            allowed_hosts=hosts,
            allowed_ips=tuple(str(item).strip() for item in _as_tuple(data.get("allowed_ips")) if str(item).strip()),
            allowed_path_prefixes=_path_rules(
                data.get("allowed_path_prefixes") or data.get("allowed_paths")
                or data.get("path_prefixes")
            ),
            forbidden=forbidden,
            allowed_methods=_method_tuple(data.get("allowed_methods") or data.get("methods")),
            allow_request_body=_as_bool(data.get("allow_request_body")),
            priority_objectives=tuple(str(item) for item in _as_tuple(
                data.get("priority_objectives") or data.get("priorities")
                or ("critical", "high", "rce")
            )),
            timeout_seconds=timeout,
            delay_seconds=delay,
        )

    def allows_method(self, method: str) -> bool:
        """Whether this authorisation document permits ``method``."""
        return str(method or "").strip().upper() in self.allowed_methods

    @property
    def requests_per_second(self) -> float:
        """The same promise as ``delay_seconds``, in the unit the program writes it in."""
        return 1.0 / self.delay_seconds if self.delay_seconds > 0 else 0.0

    def capability_line(self) -> str:
        """What this scope permits, in one line, for a prompt.

        The prompts used to hardcode "只能 GET/HEAD,不能发 POST" — true by default and
        a lie the moment a scope declares more. A model told it cannot POST while the
        sandbox would allow one simply never tries; a model told it can, when it
        cannot, writes plans that die at the gate.

        So this reports only methods the gate can actually send, and names the ones
        that were declared but are refused by semantics. PUT/PATCH are the case that
        forced the split: they are legal to declare (so a refusal can say
        ``update_semantics`` rather than ``method_not_allowed``) and impossible to send.
        """
        usable = [m for m in self.allowed_methods if m in _ADMISSIBLE_METHODS]
        refused = [m for m in self.allowed_methods if m not in _ADMISSIBLE_METHODS]
        methods = ", ".join(usable)
        if not any(m not in _SAFE_METHODS for m in usable):
            line = f"允许的方法: {methods}（这份授权只有只读方法）"
        else:
            tail = "可以带请求体" if self.allow_request_body else "不允许带请求体"
            line = f"允许的方法: {methods}（{tail}）"
        if refused:
            line += (f"。已声明但一律会被拒: {', '.join(refused)} —— 它们语义上就是"
                     "改数据,POC 不要写这类请求")
        return line

    def require_authorization(self) -> None:
        if not self.authorization:
            raise ValueError("surface_authorization_required")
        if not self.allowed_domains and not self.allowed_hosts and not self.allowed_ips:
            raise ValueError("surface_scope_required")

    def check_url(self, value: str) -> tuple[bool, str]:
        if any(ord(char) <= 32 or ord(char) == 127 for char in value):
            return False, "url_control_or_whitespace"
        parsed = urlsplit(value if "://" in value else "https://" + value)
        if parsed.scheme.lower() not in {"http", "https"}:
            return False, "unsupported_scheme"
        if parsed.username or parsed.password:
            return False, "url_credentials_not_allowed"
        try:
            parsed.port
        except ValueError:
            return False, "invalid_port"
        host = _host(parsed.hostname or "")
        if not host:
            return False, "missing_host"
        if any(_host_matches(host, item) for item in self.forbidden):
            return False, "forbidden_host"
        allowed_reason = ""
        if _is_ip(host):
            try:
                address = ipaddress.ip_address(host)
                for item in self.allowed_ips:
                    if "/" in item and address in ipaddress.ip_network(item, strict=False):
                        allowed_reason = "allowed_ip_range"
                        break
                    if address == ipaddress.ip_address(item):
                        allowed_reason = "allowed_ip"
                        break
            except ValueError:
                pass
            if not allowed_reason:
                return False, "ip_not_in_scope"
        elif any(_host_matches(host, item, descendants=True) for item in self.allowed_domains):
            allowed_reason = "allowed_domain"
        else:
            for item in self.allowed_hosts:
                exact = not _scope_host(item).startswith("*.")
                if _host_matches(host, item, descendants=not exact):
                    allowed_reason = "allowed_host"
                    break
        if not allowed_reason:
            return False, "host_not_in_scope"
        matching_rules: list[str] = []
        for entry, prefixes in self.allowed_path_prefixes:
            if entry == "*":
                matching_rules.extend(prefixes)
                continue
            exact = not _scope_host(entry).startswith("*.")
            if _host_matches(host, entry, descendants=not exact):
                matching_rules.extend(prefixes)
        if matching_rules and not any(_path_prefix_matches(parsed.path or "/", prefix)
                                     for prefix in matching_rules):
            return False, "path_not_in_scope"
        return True, allowed_reason


@dataclass
class SurfaceResult:
    target: str
    base_url: str
    # 基址跟过一跳之后落地的地址。空表示没发生重定向 —— 别拿它当"最终状态",
    # 它只回答"那一跳跳到了哪"。
    final_url: str = ""
    status: int = 0
    fingerprints: set[str] = field(default_factory=set)
    scripts: set[str] = field(default_factory=set)
    paths: set[str] = field(default_factory=set)
    api_urls: set[str] = field(default_factory=set)
    sources: dict[str, set[str]] = field(default_factory=dict)
    url_sources: dict[str, set[str]] = field(default_factory=dict)
    #: 拼接形态 -> 它是从哪个更短的路径拼出来的。跨越扫描趟的线索:.map 自己不声明 base,
    #: 所以裸碎片是那趟记的、拼接是 JS 那趟拼的 —— 结束时按这张表把来源并起来。
    joins: dict[str, set[str]] = field(default_factory=dict)
    requests: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    #: probe group -> requests actually sent (exposure / robots / framework). The
    #: crawl and the agent loop share one budget, so without this the only visible
    #: number is the total and a thin agent run looks unexplained.
    probe_spend: dict[str, int] = field(default_factory=dict)

    def add_path(self, value: str, source: str, scope: SurfaceScope) -> None:
        raw = str(value or "").strip().strip("\"'` ")
        if not raw or len(raw) > 240:
            return
        if raw.startswith(("http://", "https://", "//")):
            absolute = raw if not raw.startswith("//") else "https:" + raw
            parsed = urlsplit(absolute)
            ok, _ = scope.check_url(absolute)
            host_prefix = _host(parsed.hostname or "").split(".", 1)[0]
            if ok and (_looks_high_signal(parsed.path) or host_prefix in API_PREFIXES):
                clean = _clean_path(parsed.path, parsed.query)
                if clean:
                    self.api_urls.add(absolute.split("#", 1)[0])
                    self.url_sources.setdefault(absolute.split("#", 1)[0], set()).add(source)
            raw = urlsplit(absolute).path or "/"
        if raw.startswith(("./", "../", "//")) or not raw.startswith("/"):
            if _looks_api_relative(raw):
                raw = "/" + raw
            else:
                return
        clean = _clean_path(raw, "")
        if clean and _looks_high_signal(clean):
            self.paths.add(clean)
            self.sources.setdefault(clean, set()).add(source)

    def add_script(self, value: str, source: str, scope: SurfaceScope, base: str) -> None:
        absolute = urljoin(base, str(value or "").strip())
        if not re.search(r"\.(?:js|mjs|map|json)(?:[?#].*)?$", urlsplit(absolute).path, re.I):
            return
        ok, _ = scope.check_url(absolute)
        if ok:
            cleaned = absolute.split("#", 1)[0]
            self.scripts.add(cleaned)
            self.sources.setdefault(cleaned, set()).add(source)


class _HTMLAssets(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.assets: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {str(key).lower(): str(value) for key, value in attrs if value}
        if tag.lower() == "script" and values.get("src"):
            self.assets.append(values["src"])
        if tag.lower() == "link" and values.get("href"):
            rel = values.get("rel", "").lower()
            href = values["href"]
            if "manifest" in rel or re.search(r"\.(?:js|mjs|json)$", href, re.I):
                self.assets.append(href)


def _clean_path(path: str, query: str = "") -> str | None:
    path = str(path or "").split("#", 1)[0].strip()
    if not path.startswith("/") or len(path) > 240 or PATH_VAR_RE.search(path):
        return None
    if SKIP_RE.search(path) or STATIC_RE.search(path):
        return None
    return path + (("?" + query) if query else "")


def _looks_api_relative(value: str) -> bool:
    first = value.split("/", 1)[0].split("?", 1)[0].lower()
    return first in API_PREFIXES or bool(re.match(r"^(?:get|query|search|list|find|select)[A-Z0-9_]", value, re.I))


def _looks_high_signal(path: str) -> bool:
    """Worth a request? Either it routes somewhere, or it leaks something."""
    value = (path or "").lower()
    first = value.lstrip("/").split("/", 1)[0].split("?", 1)[0]
    return (first in API_PREFIXES or "/api/" in value
            or bool(DISCOVERY_RE.search(value)) or bool(EXPOSURE_RE.search(value)))


def _fingerprints(text: str, content_type: str) -> set[str]:
    lower = text.lower()
    checks = {
        "Vue": ("vue", "__vue__", "vue-router"),
        "React": ("react", "__react", "reactdom", "react-router"),
        "Angular": ("ng-version", "angular", "ng-app"),
        "Next.js": ("__next_data__", "/_next/static/"),
        "Nuxt": ("__nuxt__", "/_nuxt/"),
        "Vite": ("/@vite/client", "import.meta.env"),
        "Webpack": ("webpackjsonp", "__webpack_require__", "webpackchunk"),
        "Swagger/OpenAPI": ("swagger-ui", '"openapi"', '"swagger"'),
    }
    found = {name for name, needles in checks.items() if any(needle in lower for needle in needles)}
    if "json" in content_type.lower() and ("paths" in lower or "swagger" in lower):
        found.add("OpenAPI JSON")
    return found


def _response_content_type(headers: Mapping[str, str]) -> str:
    return next((str(value).split(";", 1)[0].strip().lower()
                 for key, value in headers.items() if str(key).lower() == "content-type"), "")


def _normalized_response_text(text: str, request_url: str) -> str:
    """Normalize only volatile request IDs and the requested path for template comparison."""
    value = str(text or "").lower()[:8_000]
    path = urlsplit(request_url).path.lower().rstrip("/")
    if path:
        value = value.replace(path, "<request-path>")
    value = re.sub(
        r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
        "<request-id>", value,
    )
    # Login shells commonly stamp a fresh CSP nonce on every response.  Leaving
    # it in the comparison makes the same auth page look like a real endpoint.
    value = re.sub(r"\bnonce\s*=\s*(['\"]).*?\1", "nonce=<nonce>", value)
    value = re.sub(r"\bnonce\s*:\s*(['\"]).*?\1", "nonce:<nonce>", value)
    value = re.sub(r"\b[0-9a-f]{20,}\b", "<request-id>", value)
    value = re.sub(r"\b\d{10,}\b", "<request-number>", value)
    return re.sub(r"\s+", " ", value).strip()


def _looks_authentication_gate(text: str) -> bool:
    """Recognize a login wrapper, including 200 responses used for redirects."""
    value = str(text or "")
    return bool(re.search(
        r"(?:no_cookie_session|session-service/login|accounts\.shopify\.com/[^\"'<> ]*login"
        r"|shopify[-_ ]password|storefront[-_ ]password"
        r"|<(?:div|meta)\b[^>]*(?:data-url|http-equiv)=[^>]*(?:login|sign[-_ ]?in)"
        r"|<form\b[^>]*action=[\"'][^\"']*/password(?:[\"'/? >]))",
        value, re.I,
    ))


def _matches_soft_404(
    status: int,
    text: str,
    headers: Mapping[str, str],
    url: str,
    baseline: tuple[int, str, Mapping[str, str], str] | None,
) -> bool:
    """Match a successful response against one random-path response conservatively."""
    if baseline is None:
        return False
    baseline_status, baseline_text, baseline_headers, baseline_url = baseline
    if not (200 <= status < 300 and status == baseline_status and baseline_text):
        return False
    if _response_content_type(headers) != _response_content_type(baseline_headers):
        return False
    candidate_title = re.search(r"<title\b[^>]*>(.*?)</title>", text, re.I | re.S)
    baseline_title = re.search(r"<title\b[^>]*>(.*?)</title>", baseline_text, re.I | re.S)
    if candidate_title and baseline_title:
        left_title = _normalized_response_text(candidate_title.group(1), url)
        right_title = _normalized_response_text(baseline_title.group(1), baseline_url)
        if left_title != right_title:
            return False
    left = _normalized_response_text(text, url)
    right = _normalized_response_text(baseline_text, baseline_url)
    if not left or not right:
        return False
    if min(len(left), len(right)) < 80:
        return left == right
    if max(len(left), len(right)) > min(len(left), len(right)) * 1.25:
        return False
    return SequenceMatcher(None, left, right, autojunk=False).ratio() >= 0.985


def _extract_text(text: str, result: SurfaceResult, source: str, scope: SurfaceScope,
                  *, bases: tuple[str, ...] = ()) -> None:
    for regex in (URL_RE, QUOTED_PATH_RE, FIELD_RE, ROUTER_RE):
        for match in regex.finditer(text):
            value = match.group(1) if match.lastindex else match.group(0)
            result.add_path(value, source, scope)
            _add_under_bases(result, value, bases, scope, source=source)


#: How many declared bases one bundle may contribute. A file that declares ten of them is
#: not telling us anything more useful than a file that declares two.
MAX_API_BASES = 4

#: 连接层失败(``status == 0``)时,同一个 URL 再试几次。实测(2026-09-23,login-dev.nba.com)
#: app bundle 单次返回 0,而它正是**唯一**声明 `/openidm` 的文件 —— 整轮爬取因此从 31 条候选
#: 掉到 4 条(剩下的是 vendor 的 sourcemap),摘要里一个字都没提。4xx/5xx 是对方的回答,不重试。
#:
#: 三次(首发 + 两次重试)取的是和 ``_httpx_provider`` 同一个数。代价要说清楚:对一个**真的**
#: 不可达的主机,这三发每发都要等满一次 timeout(scope 里是 8s),而且每发都吃一份额度 ——
#: 拿 2 份额度换"整轮运行不因为一次掉线作废",这个交换在 60 一份的预算下是划算的。真嫌慢就
#: 把 4xx/5xx 也一起重试的路子排除掉,别把这个数当成可以随手调的旋钮。
TRANSIENT_FETCH_RETRIES = 2


# A bundle that declares its own API base makes its relative paths resolvable, and the
# paths it contains are usually *fragments* of that base rather than URLs. ForgeRock's End
# User UI is the worked example:
#
#     VUE_APP_IDM_URL:"/openidm"          ← the base, declared
#     var h="/config/ui/themerealm"        ← a fragment
#     return"/openidm/config/managed"      ← the join, once, as a literal
#
# so the bundle yields `/config/ui/themerealm`, which is not a URL and 404s, while the real
# endpoint is `/openidm/config/ui/themerealm`. Measured 2026-09-21 on login-dev.nba.com: the
# hunt spent its three OPTIONS probes on unprefixed paths and got three 404s.
_API_BASE_RE = re.compile(
    r"""(?ix)
    ["']?[A-Za-z_][\w.\-]*(?:url|base|prefix|root|endpoint)["']?   # a base-ish key …
    \s*[:=]\s*
    ["'](/(?!/)[A-Za-z][\w.\-]{0,40})["']                          # … holding one path segment
    """
)


def _declared_api_bases(text: str) -> tuple[str, ...]:
    """Path roots this bundle both declares **and uses**.

    The "and uses" half is the whole point: a base only counts if some literal in the same
    text already starts with it, so the bundle proves the join itself. Without that check a
    ``avatar_url:"/img"`` would manufacture a whole family of paths that never existed and
    every one of them would be a wasted request.

    Known imprecision, measured: the ForgeRock bundle also contains
    ``VUE_APP_AM_ADMIN_URL:"/am/ui-admin/"``, which confirms ``/am`` — a *declared value*
    rather than a genuine join. That one is harmless because ``/am`` really is a base (the
    Access Management REST API lives at ``/am/json/…``), but the rule is "some literal
    starts with it", not "some literal is a join of it".
    """
    declared = {match.group(1) for match in _API_BASE_RE.finditer(text)}
    confirmed = sorted(
        base for base in declared
        if f'"{base}/' in text or f"'{base}/" in text or f"`{base}/" in text
    )
    return tuple(confirmed[:MAX_API_BASES])


def _add_under_bases(result: SurfaceResult, value: str, bases: tuple[str, ...],
                     scope: SurfaceScope, *, source: str = "") -> None:
    """Also record ``base + fragment`` for every declared base.

    The fragment is kept as well — sometimes it really is a path. But the joined form is the
    *same discovery* with one more piece of evidence (the bundle said the base out loud), so it
    carries the fragment's source too and can never rank below it. Without that inheritance the
    two entries were the same finding wearing different provenance, and the bundle's own
    evidence lost to whichever extractor happened to name the fragment:

    实测(2026-09-23,login-dev.nba.com 三趟):裸碎片带 ``sourcemap``(25) → 70 分,拼接形态只带
    ``base-join``(18) → 63 分,于是模型打了 101 发裸的、12 发拼接的;两形态同时在清单里的
    3 个族里,裸的一律 404,拼接的那条是活的(200 / OPTIONS 200)。
    """
    if not bases:
        return
    raw = str(value or "").strip()
    if not raw.startswith("/") or raw.startswith("//"):
        return
    if "#" in raw or STATIC_RE.search(raw):
        return  # a fragment or a static asset is not an API path
    path = raw.split("?", 1)[0]
    if len(path) < 2:
        return
    if any(path == base or path.startswith(base + "/") for base in bases):
        return  # already carries a base — nothing to resolve
    for base in bases:
        joined = f"{base}{raw}"
        fragment = _clean_path(path, "")
        result.add_path(joined, "base-join", scope)
        result.joins.setdefault(joined, set()).add(fragment)
        if source:
            # 来源跟着一起继承:拼接形态是碎片解析出来的,不是第二次发现。同一趟里的那份
            # 在这里就并上了;别的趟记下的那份由 ``_inherit_joined_sources`` 在收尾时并。
            result.add_path(joined, source, scope)


def _inherit_joined_sources(result: SurfaceResult) -> None:
    """把裸碎片的**全部**来源并给拼接形态,不管碎片是哪一趟记下的。

    同一趟里继承不够——真实文件是分开的:扫 JS 那趟声明了 ``/openidm`` 并拼出
    ``/openidm/config/ui/themerealm``(来源 js),而裸碎片 ``/config/ui/themerealm`` 是扫
    ``*.map`` 那趟记下的(来源 sourcemap,权重 25)。两趟各自只有一个来源,只有合起来才看得出
    "这是同一次发现"。

    实测(2026-09-23,login-dev.nba.com):不并这一下,拼接形态 69 分,反而比裸碎片的 70 分低
    —— 模型照样打 404 的那条。并上之后再靠 ``_RESOLVED_FRAGMENT_BONUS`` 稳定地压过它。
    """
    for joined, fragments in result.joins.items():
        names = result.sources.get(joined)
        if not names:
            continue
        for fragment in fragments:
            names |= result.sources.get(fragment, set())


def _extract_json(text: str, result: SurfaceResult, source: str, scope: SurfaceScope, base: str,
                  *, bases: tuple[str, ...] = ()) -> None:
    try:
        value = json.loads(text)
    except (TypeError, ValueError):
        _extract_text(text, result, source, scope, bases=bases)
        return

    def walk(item: Any) -> None:
        if isinstance(item, Mapping):
            for key, child in item.items():
                if key == "paths" and isinstance(child, Mapping):
                    for path in child:
                        result.add_path(str(path), "openapi", scope)
                if key == "sourcesContent" and isinstance(child, list):
                    for source_text in child[:60]:
                        if isinstance(source_text, str):
                            _extract_text(source_text, result, "sourcemap", scope, bases=bases)
                walk(child)
        elif isinstance(item, list):
            for child in item:
                walk(child)
        elif isinstance(item, str):
            if re.search(r"\.(?:js|mjs|map|json)(?:[?#].*)?$", item, re.I):
                result.add_script(item, source, scope, base)
            result.add_path(item, source, scope)

    walk(value)


def _extract_robots(text: str, result: SurfaceResult, scope: SurfaceScope) -> None:
    for line in text.splitlines():
        line = line.strip()
        if ":" in line and line.lower().startswith(("allow:", "disallow:", "sitemap:")):
            result.add_path(line.split(":", 1)[1].strip(), "robots", scope)
        elif line.startswith("<loc>") and "</loc>" in line:
            result.add_path(line.split("<loc>", 1)[1].split("</loc>", 1)[0], "sitemap", scope)


def _decompress_http_body(payload: bytes, content_encoding: str = "") -> bytes:
    """Undo Content-Encoding so extractors see HTML/JS, not the wire bytes.

    urllib does not decompress. Many CDNs gzip regardless of ``Accept-Encoding``;
    the body starts with ``\\x1f\\x8b`` while Content-Type still says text/html.
    Passing that blob to the HTML parser yields zero scripts and zero paths, which
    looks like "this host has no surface". Truncated reads (``max_bytes``) still
    yield whatever prefix zlib can inflate.
    """
    if not payload:
        return payload
    encoding = (content_encoding or "").split(",")[0].strip().lower()
    looks_gzip = encoding in {"gzip", "x-gzip"} or payload.startswith(b"\x1f\x8b")
    if looks_gzip:
        try:
            decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
            out = decoder.decompress(payload) + decoder.flush()
            return out or payload
        except zlib.error:
            return payload
    if encoding == "deflate":
        for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
            try:
                return zlib.decompress(payload, wbits)
            except zlib.error:
                continue
        return payload
    return payload


def _decode_http_body(payload: bytes, headers: Mapping[str, str]) -> str:
    raw = _decompress_http_body(payload, headers.get("content-encoding", ""))
    charset_match = re.search(r"charset=([\w.-]+)", headers.get("content-type", ""), re.I)
    charset = charset_match.group(1) if charset_match else "utf-8"
    try:
        return raw.decode(charset, errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


def _request_text(
    method: str,
    url: str,
    *,
    timeout: float,
    max_bytes: int = 1_500_000,
    body: bytes | None = None,
    content_type: str = "",
) -> tuple[int, str, dict[str, str]]:
    """The one place a request is actually sent.

    Every method goes through here, so there is exactly one thing to audit and one
    place where the transport is decided. The method is passed to :class:`Request`
    rather than defaulted — a HEAD that quietly ran as a GET would make the audit
    trail a lie, which is worse than not having one.
    """
    headers = {
        "User-Agent": "pentest-agent-src-surface/1.0",
        "Accept": "text/html,application/json,text/plain,*/*;q=0.5",
        # urllib defaults to identity if this is missing. We accept gzip and undo
        # it ourselves; several authorized hosts gzip even when identity is asked.
        "Accept-Encoding": "gzip, deflate",
    }
    if body:
        headers["Content-Type"] = content_type or "application/x-www-form-urlencoded"
    request = Request(url, data=body or None, headers=headers, method=str(method).upper())
    # Verified TLS first. A broken chain on an *authorized* host used to look like
    # "unreachable" (status 0) and the crawl never started. Retry once without
    # verify so the HTML is still collected; the response is stamped so the
    # fingerprint can say why.
    contexts: tuple[ssl.SSLContext | None, ...] = (None, ssl._create_unverified_context())
    last_error: Exception | None = None
    for index, context in enumerate(contexts):
        opener = build_opener(_NoRedirect()) if context is None else build_opener(
            _NoRedirect(), HTTPSHandler(context=context))
        try:
            with opener.open(request, timeout=timeout) as response:
                payload = response.read(max_bytes)
                headers = {str(key).lower(): str(value) for key, value in response.headers.items()}
                if index:
                    headers["x-lode-tls"] = "certificate_verify_failed"
                return int(response.status), _decode_http_body(payload, headers), headers
        except HTTPError as exc:
            # 把响应头留下:3xx 的 Location 就在这里面,后面跟一跳要用。正文也留下 —
            # 401/403 的 JSON 错误体经常带着真正的 API 路径,丢掉就等于丢掉面。
            headers = {str(key).lower(): str(value) for key, value in (exc.headers or {}).items()}
            try:
                payload = exc.read(max_bytes)
            except Exception:
                payload = b""
            if index:
                headers["x-lode-tls"] = "certificate_verify_failed"
            return int(exc.code), _decode_http_body(payload, headers) if payload else "", headers
        except (OSError, URLError, TimeoutError, ValueError) as exc:
            last_error = exc
            if index == 0 and _tls_verify_failed(exc):
                continue
            return 0, "", {}
    del last_error
    return 0, "", {}


def _tls_verify_failed(exc: BaseException) -> bool:
    return "CERTIFICATE_VERIFY_FAILED" in str(exc)


def _fetch_text(url: str, *, timeout: float, max_bytes: int = 1_500_000) -> tuple[int, str, dict[str, str]]:
    """GET. Name and signature unchanged on purpose — this is the injected seam that
    nine existing tests hand a fake fetcher to."""
    return _request_text("GET", url, timeout=timeout, max_bytes=max_bytes)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def discover_surface(
    scope: SurfaceScope,
    target: str,
    *,
    max_scripts: int = 40,
    fetcher: Callable[..., tuple[int, str, dict[str, str]]] | None = None,
    budget: Any = None,
    extra_seeds: Sequence[str] = (),
) -> SurfaceResult:
    scope.require_authorization()
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    parsed = urlsplit(target)
    base = urlunsplit((parsed.scheme.lower(), parsed.netloc, "", "", ""))
    start = target.rstrip("/") or base
    ok, reason = scope.check_url(start)
    if not ok:
        raise ValueError("target_rejected:" + reason)
    read_reason = _readonly_url_reason(start)
    if read_reason:
        raise ValueError("target_rejected:" + read_reason)
    result = SurfaceResult(target=target, base_url=base)
    get = fetcher or _fetch_text
    # 限速不在这层记账了:每个调用点自己数 last_request 就是"每个 worker 一份配额",
    # 起 N 个 worker 就等于把程序写明的 req/s 乘 N。桶是全局的,见 core/rate_limit。
    limiter = limiter_for(scope)

    def fetch(url: str, *, follow: bool = True) -> tuple[int, str, dict[str, str]]:
        ok, reason = scope.check_url(url)
        if not ok:
            result.errors.append(f"blocked:{_safe_logged_url(url)}:{reason}")
            return 0, "", {}
        read_reason = _readonly_url_reason(url)
        if read_reason:
            result.errors.append(f"blocked:{_safe_logged_url(url)}:{read_reason}")
            return 0, "", {}
        # 爬虫是 GET 流量的最大来源(SEED_PATHS 加上 max_scripts 个脚本各一跳),所以它
        # 也要吃同一份额度 —— 只让 agent 侧计数等于把大头漏掉了。被拦掉的请求不计。
        def _attempt() -> tuple[int, str, dict[str, str]]:
            if limiter is not None:
                limiter.acquire(url)
            outcome = get(url, timeout=scope.timeout_seconds, max_bytes=1_500_000)
            result.requests.append({"url": _safe_logged_url(url), "status": outcome[0]})
            return outcome

        if budget is not None and not budget.spend():
            result.errors.append(f"blocked:{_safe_logged_url(url)}:request_budget_exhausted")
            return 0, "", {}
        status, text, headers = _attempt()
        if headers.get("x-lode-tls") == "certificate_verify_failed":
            result.fingerprints.add("TLS certificate verify failed")
        # ``status == 0`` 是连接层没成,不是对方的回答 —— 一次掉线不等于"这个资产不存在"。
        # 重试照走同一条路:闸门、额度、限速一步都不跳(它也是真的一次出站)。4xx/5xx 不在这里
        # 重试,那是对方明确回答过了。
        for _ in range(TRANSIENT_FETCH_RETRIES):
            if status != 0:
                break
            if budget is not None and not budget.spend():
                result.errors.append(f"blocked:{_safe_logged_url(url)}:request_budget_exhausted")
                break
            status, text, headers = _attempt()
        if status == 0:
            # 试到底还是不行就记下来。以前这里是静默的:结果差一大截,而摘要里看不出原因。
            result.errors.append(f"unreachable:{_safe_logged_url(url)}")
        if follow and 300 <= status < 400:
            # 跟一跳。不跟的话,回 301/302 的站正文一个字节都取不到,面就是空的 ——
            # 看上去像"这个站没东西",其实是重定向没走(login 跳到 /login/、
            # stats 跳到别的站,都是这种)。
            #
            # 只跟一跳(``follow=False`` 掐死递归),而且跳过去的目标要重新走一遍
            # 这个函数:scope 闸门、只读闸门、限速一样不能少。重定向可以指向任何
            # 地方,包括授权范围外 —— 不能因为它是"跳转"就放行。被闸门拦下时
            # 这里原样返回那个 3xx,不假装跳成功。
            location = str(headers.get("location") or "").strip()
            if location:
                hop = urljoin(url, location)
                if hop == url:
                    result.errors.append(f"redirect_loop:{_safe_logged_url(url)}")
                    return status, text, headers
                hop_status, hop_text, hop_headers = fetch(hop, follow=False)
                if hop_status:
                    # 只有真跳成了才记下来 —— 被闸门拦下的那一跳不算"落点",
                    # 否则 final_url 会写成一个我们从没请求过的站外地址。
                    result.requests[-1]["redirected_to"] = _safe_logged_url(hop)
                    return hop_status, hop_text, hop_headers
        return status, text, headers

    started_at = len(result.requests)
    status, html, headers = fetch(start + ("/" if not parsed.path else ""))
    result.status = status
    # 基址跳走了的话,落地的地址才是这个站真正的根 —— 后面 robots/sitemap/相对
    # 脚本链接都要按它解析,否则从 /login/ 页里抽出来的资源会挂到旧根上。
    final_url = next((str(row.get("redirected_to")) for row in result.requests[started_at:]
                      if row.get("redirected_to")), "")
    if final_url:
        result.final_url = final_url
        landed = urlsplit(final_url)
        base = urlunsplit((landed.scheme.lower(), landed.netloc, "", "", ""))
        start = final_url.rstrip("/") or base
    result.fingerprints.update(_fingerprints(html, headers.get("content-type", "")))
    if _looks_authentication_gate(html):
        result.fingerprints.add("authentication-gated")
    try:
        from intel.wih import tag_text
        result.fingerprints.update(tag_text(html))
    except Exception:
        pass
    if status == 0:
        result.errors.append("base_unreachable")
        return result
    _extract_text(html, result, "html", scope)
    parser = _HTMLAssets()
    try:
        parser.feed(html)
    except Exception:
        result.errors.append("html_parse_error")
    for asset in parser.assets:
        result.add_script(asset, "html", scope, start + "/")

    if 300 <= status < 400:
        result.fingerprints.add("redirect-chain-incomplete")
        return result

    # A 429 is an explicit server-side throttle.  Continuing with the fixed
    # probe list only increases pressure and cannot improve the evidence.  A
    # 200 login/password shell is equally uninformative without an authenticated
    # browser capture, so leave a clear marker and wait for that evidence instead.
    if status == 429:
        result.fingerprints.add("rate-limited")
        return result
    if _looks_authentication_gate(html):
        return result

    extra = tuple(str(item).strip() for item in extra_seeds if str(item).strip())
    extra_set = set(extra)
    soft404_baseline: tuple[int, str, Mapping[str, str], str] | None = None
    soft404_baseline_attempted = False
    for seed in tuple(SEED_PATHS) + extra:
        seed_url = urljoin(base + "/", seed.lstrip("/"))
        sent_before = len(result.requests)
        seed_status, text, seed_headers = fetch(seed_url)
        # Book only the probes that actually went out: a budget-exhausted or
        # scope-blocked probe spends nothing and must not read as spend.
        if len(result.requests) > sent_before:
            group = ("exposure" if seed in EXPOSURE_PATHS
                     else "robots" if seed.endswith(("robots.txt", "sitemap.xml"))
                     else "fingerprint" if seed in extra_set
                     else "framework")
            # Retries and in-scope redirects can add more than one outbound
            # request for this logical probe. Report actual requests so the
            # metric reconciles with the shared request budget.
            result.probe_spend[group] = result.probe_spend.get(group, 0) + (
                len(result.requests) - sent_before
            )
        if not text or seed_status == 0:
            continue
        if _looks_authentication_gate(text):
            result.fingerprints.add("authentication-gated")
        if 200 <= seed_status < 300 and text != html and text.strip():
            # Calibrate once, and only when a successful probe differs from the root.
            # The request uses the normal scope, rate and shared-budget gates above.
            if not soft404_baseline_attempted:
                soft404_baseline_attempted = True
                nonce = secrets.token_hex(12)
                baseline_url = urljoin(base + "/", f"__lode_miss__/{nonce}")
                baseline_sent_before = len(result.requests)
                baseline_status, baseline_text, baseline_headers = fetch(baseline_url)
                actual_spend = len(result.requests) - baseline_sent_before
                if actual_spend:
                    result.probe_spend["quality"] = result.probe_spend.get("quality", 0) + actual_spend
                if 200 <= baseline_status < 300 and baseline_text:
                    soft404_baseline = (
                        baseline_status, baseline_text, baseline_headers, baseline_url,
                    )
            if _matches_soft_404(seed_status, text, seed_headers, seed_url, soft404_baseline):
                result.fingerprints.add("soft-404 fallback")
                continue
        result.fingerprints.update(_fingerprints(text, seed_headers.get("content-type", "")))
        if seed in extra_set:
            try:
                from intel.fingerprint import match_body
                result.fingerprints.update(match_body(text))
            except Exception:
                pass
            try:
                from intel.wih import tag_text
                result.fingerprints.update(tag_text(text))
            except Exception:
                pass
        # A probe that answers 2xx with its own body is itself a discovered path. The
        # seeds used to be mined for content only, so a file's *existence* was never
        # recorded — `/.env` answered 200 and still never became a candidate.
        # `text != html` is the soft-404 guard: a site that returns its index page for
        # every path (SPA shells — the NBA case) would otherwise manufacture surface
        # out of nothing, which is a worse failure than the one being fixed.
        if 200 <= seed_status < 300 and text != html:
            result.add_path(seed, "seed", scope)
        if seed.endswith(("robots.txt", "sitemap.xml")):
            _extract_robots(text, result, scope)
        elif seed.endswith((".json", ".yaml")) or "openapi" in seed or "swagger" in seed or "manifest" in seed:
            _extract_json(text, result, "seed", scope, seed_url)
        else:
            _extract_text(text, result, "seed", scope)

    queue = list(result.scripts)
    processed: set[str] = set()
    while queue and len(processed) < max(1, min(int(max_scripts), 100)):
        script_url = queue.pop(0)
        if script_url in processed:
            continue
        processed.add(script_url)
        script_status, text, script_headers = fetch(script_url)
        if script_status == 0 or not text:
            continue
        result.fingerprints.update(_fingerprints(text, script_headers.get("content-type", "")))
        try:
            from intel.wih import tag_text
            result.fingerprints.update(tag_text(text))
        except Exception:
            pass
        # 这个 bundle 自己声明了 API base 的话,它里面的相对片段就是拼上 base 才成立的。
        bases = _declared_api_bases(text)
        if urlsplit(script_url).path.lower().endswith(".map"):
            _extract_json(text, result, "sourcemap", scope, script_url, bases=bases)
            continue
        _extract_text(text, result, "js", scope, bases=bases)
        before = set(result.scripts)
        for match in SOURCE_MAP_RE.findall(text):
            result.add_script(match, "js", scope, script_url)
        for match in CHUNK_RE.findall(text):
            result.add_script(match, "js", scope, script_url)
        queue.extend(sorted(result.scripts - before - processed))
    # 所有趟都扫完了才谈继承:拼接形态和它的裸碎片可能分别落在 JS 与 .map 两趟里。
    _inherit_joined_sources(result)
    return result


def surface_to_dict(result: SurfaceResult) -> dict[str, Any]:
    safe_api_urls = sorted(_safe_logged_url(url) for url in result.api_urls)
    safe_url_sources = {
        _safe_logged_url(key): sorted(value)
        for key, value in sorted(result.url_sources.items())
    }
    return {
        "schema": "SrcSurfaceResult/v1",
        "target": _safe_logged_url(result.target),
        "base_url": result.base_url,
        "final_url": _safe_logged_url(result.final_url),
        "status": result.status,
        "fingerprints": sorted(result.fingerprints),
        "scripts": sorted(result.scripts),
        "paths": sorted(result.paths),
        "api_urls": safe_api_urls,
        "sources": {key: sorted(value) for key, value in sorted(result.sources.items())},
        "url_sources": safe_url_sources,
        "requests": result.requests,
        "errors": result.errors,
        "probe_spend": dict(sorted(result.probe_spend.items())),
    }


def render_surface_markdown(result: SurfaceResult) -> str:
    lines = [
        "# SRC Surface Discovery",
        "",
        f"- target: `{_safe_logged_url(result.target)}`",
        f"- status: `{result.status}`",
        f"- requests: `{len(result.requests)}`",
        f"- fingerprints: `{', '.join(sorted(result.fingerprints)) or '-'}`",
        "",
        "## Candidate paths",
        "",
    ]
    lines.extend(f"- `{path}` source={','.join(sorted(result.sources.get(path, ()))) or '-'}" for path in sorted(result.paths))
    if result.api_urls:
        lines.extend(["", "## In-scope absolute API URLs", ""])
        lines.extend(
            f"- `{_safe_logged_url(url)}` source={','.join(sorted(result.url_sources.get(url, ()))) or '-'}"
            for url in sorted(result.api_urls)
        )
    if result.errors:
        lines.extend(["", "## Errors", ""])
        lines.extend(f"- `{error}`" for error in result.errors[:30])
    return "\n".join(lines) + "\n"


def write_surface_outputs(result: SurfaceResult, out_dir: str | Path) -> tuple[Path, Path]:
    output = Path(out_dir)
    output.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^a-zA-Z0-9._-]+", "-", _safe_logged_url(result.target)).strip("-")[:80] or "target"
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    json_path = output / f"surface-{stamp}-{safe}.json"
    md_path = output / f"surface-{stamp}-{safe}.md"
    json_path.write_text(json.dumps(surface_to_dict(result), ensure_ascii=False, indent=2), encoding="utf-8")
    md_path.write_text(render_surface_markdown(result), encoding="utf-8")
    return json_path, md_path
