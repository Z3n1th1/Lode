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
import ssl
import time
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

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
}
DISCOVERY_RE = re.compile(
    r"(?:^|/)(?:swagger|api-docs|openapi|graphql|graphiql|actuator|healthz?|"
    r"readyz?|livez?|status|version|metrics|info|config|schema)(?:/|$|[.?_-])",
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

SEED_PATHS = (
    "/asset-manifest.json", "/manifest.json", "/static/js/manifest.json",
    "/build/asset-manifest.json", "/webpack-manifest.json", "/swagger.json",
    "/swagger/v1/swagger.json", "/swagger/v2/swagger.json", "/api-docs",
    "/api-docs.json", "/v2/api-docs", "/v3/api-docs", "/openapi.json",
    "/openapi.yaml", "/swagger-ui.html", "/graphql", "/graphiql",
    "/robots.txt", "/sitemap.xml",
)


def _host(value: str) -> str:
    return str(value or "").strip().lower().strip("[]").rstrip(".")


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
    return state_changing_reason(value)


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
    forbidden: tuple[str, ...] = ()
    # 能力维度:这份授权文档允许**做什么**,不只是允许**去哪里**。
    #
    # 以前只读是 agents/src_agent.py 里一个硬编码的 {"GET","HEAD"},所以授权文档从
    # 来没有说过"这个 worker 可以做什么" —— 想放宽就只能在代码里放宽,那是把治理
    # 从句面搬进源码。默认仍然只有 GET/HEAD,而且是恒并集:声明什么都拿不掉。
    allowed_methods: tuple[str, ...] = _SAFE_METHODS
    # 允许带请求体。单独一个开关,因为"可以发 POST"和"可以发任意 body"是两件事。
    allow_request_body: bool = False
    timeout_seconds: float = 8.0
    delay_seconds: float = 0.4

    def __post_init__(self) -> None:
        # 归一化放在类型上,不只放在 from_mapping 里:直接构造 SurfaceScope 的调用方
        # 同样不该拿到一份"GET/HEAD 被声明掉"的授权。幂等,所以两种路径的结果一致。
        object.__setattr__(self, "allowed_methods", _method_tuple(self.allowed_methods))

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
            forbidden=forbidden,
            allowed_methods=_method_tuple(data.get("allowed_methods") or data.get("methods")),
            allow_request_body=_as_bool(data.get("allow_request_body")),
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
        if _is_ip(host):
            try:
                address = ipaddress.ip_address(host)
                for item in self.allowed_ips:
                    if "/" in item and address in ipaddress.ip_network(item, strict=False):
                        return True, "allowed_ip_range"
                    if address == ipaddress.ip_address(item):
                        return True, "allowed_ip"
            except ValueError:
                pass
            return False, "ip_not_in_scope"
        if any(_host_matches(host, item, descendants=True) for item in self.allowed_domains):
            return True, "allowed_domain"
        for item in self.allowed_hosts:
            exact = not _scope_host(item).startswith("*.")
            if _host_matches(host, item, descendants=not exact):
                return True, "allowed_host"
        return False, "host_not_in_scope"


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
    requests: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

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
    value = (path or "").lower()
    first = value.lstrip("/").split("/", 1)[0].split("?", 1)[0]
    return first in API_PREFIXES or "/api/" in value or bool(DISCOVERY_RE.search(value))


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


def _extract_text(text: str, result: SurfaceResult, source: str, scope: SurfaceScope) -> None:
    for regex in (URL_RE, QUOTED_PATH_RE, FIELD_RE, ROUTER_RE):
        for match in regex.finditer(text):
            result.add_path(match.group(1) if match.lastindex else match.group(0), source, scope)


def _extract_json(text: str, result: SurfaceResult, source: str, scope: SurfaceScope, base: str) -> None:
    try:
        value = json.loads(text)
    except (TypeError, ValueError):
        _extract_text(text, result, source, scope)
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
                            _extract_text(source_text, result, "sourcemap", scope)
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
    }
    if body:
        headers["Content-Type"] = content_type or "application/x-www-form-urlencoded"
    request = Request(url, data=body or None, headers=headers, method=str(method).upper())
    opener = build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:
            payload = response.read(max_bytes)
            headers = {str(key).lower(): str(value) for key, value in response.headers.items()}
            charset_match = re.search(r"charset=([\w.-]+)", headers.get("content-type", ""), re.I)
            charset = charset_match.group(1) if charset_match else "utf-8"
            return int(response.status), payload.decode(charset, errors="replace"), headers
    except HTTPError as exc:
        # 把响应头留下:3xx 的 Location 就在这里面,后面跟一跳要用。
        return int(exc.code), "", {str(key).lower(): str(value) for key, value in (exc.headers or {}).items()}
    except (OSError, URLError, TimeoutError, ValueError):
        return 0, "", {}


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
            result.errors.append(f"blocked:{url}:{reason}")
            return 0, "", {}
        read_reason = _readonly_url_reason(url)
        if read_reason:
            result.errors.append(f"blocked:{url}:{read_reason}")
            return 0, "", {}
        # 爬虫是 GET 流量的最大来源(SEED_PATHS 加上 max_scripts 个脚本各一跳),所以它
        # 也要吃同一份额度 —— 只让 agent 侧计数等于把大头漏掉了。被拦掉的请求不计。
        if budget is not None and not budget.spend():
            result.errors.append(f"blocked:{url}:request_budget_exhausted")
            return 0, "", {}
        if limiter is not None:
            limiter.acquire(url)
        status, text, headers = get(url, timeout=scope.timeout_seconds, max_bytes=1_500_000)
        result.requests.append({"url": url, "status": status})
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
                hop_status, hop_text, hop_headers = fetch(hop, follow=False)
                if hop_status:
                    # 只有真跳成了才记下来 —— 被闸门拦下的那一跳不算"落点",
                    # 否则 final_url 会写成一个我们从没请求过的站外地址。
                    result.requests[-1]["redirected_to"] = hop
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

    for seed in SEED_PATHS:
        seed_url = urljoin(base + "/", seed.lstrip("/"))
        seed_status, text, seed_headers = fetch(seed_url)
        if not text or seed_status == 0:
            continue
        result.fingerprints.update(_fingerprints(text, seed_headers.get("content-type", "")))
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
        if urlsplit(script_url).path.lower().endswith(".map"):
            _extract_json(text, result, "sourcemap", scope, script_url)
            continue
        _extract_text(text, result, "js", scope)
        before = set(result.scripts)
        for match in SOURCE_MAP_RE.findall(text):
            result.add_script(match, "js", scope, script_url)
        for match in CHUNK_RE.findall(text):
            result.add_script(match, "js", scope, script_url)
        queue.extend(sorted(result.scripts - before - processed))
    return result


def surface_to_dict(result: SurfaceResult) -> dict[str, Any]:
    return {
        "schema": "SrcSurfaceResult/v1",
        "target": result.target,
        "base_url": result.base_url,
        "final_url": result.final_url,
        "status": result.status,
        "fingerprints": sorted(result.fingerprints),
        "scripts": sorted(result.scripts),
        "paths": sorted(result.paths),
        "api_urls": sorted(result.api_urls),
        "sources": {key: sorted(value) for key, value in sorted(result.sources.items())},
        "url_sources": {key: sorted(value) for key, value in sorted(result.url_sources.items())},
        "requests": result.requests,
        "errors": result.errors,
    }


def render_surface_markdown(result: SurfaceResult) -> str:
    lines = [
        "# SRC Surface Discovery",
        "",
        f"- target: `{result.target}`",
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
        lines.extend(f"- `{url}` source={','.join(sorted(result.url_sources.get(url, ()))) or '-'}" for url in sorted(result.api_urls))
    if result.errors:
        lines.extend(["", "## Errors", ""])
        lines.extend(f"- `{error}`" for error in result.errors[:30])
    return "\n".join(lines) + "\n"


def write_surface_outputs(result: SurfaceResult, out_dir: str | Path) -> tuple[Path, Path]:
    output = Path(out_dir)
    output.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^a-zA-Z0-9._-]+", "-", result.target).strip("-")[:80] or "target"
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    json_path = output / f"surface-{stamp}-{safe}.json"
    md_path = output / f"surface-{stamp}-{safe}.md"
    json_path.write_text(json.dumps(surface_to_dict(result), ensure_ascii=False, indent=2), encoding="utf-8")
    md_path.write_text(render_surface_markdown(result), encoding="utf-8")
    return json_path, md_path
