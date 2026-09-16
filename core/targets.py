"""把一个粘贴进来的目标清单拆成:入口 URL / 域名 / 精确主机。

对话和建卡两条路都走这里,所以它同时是**范围分类的唯一来源**和 **SSRF 闸门的位置**。

分类规则(操作员可见,确认单上原样显示两栏):

| 写法 | 算作 | 含义 |
|---|---|---|
| ``*.x.com`` | 域名 | 含所有子域 |
| ``x.com`` | 域名 | 两段 = apex,含所有子域 |
| ``www.x.com`` | 精确主机 | 只有这一个主机 |
| ``https://x/y`` | 入口 URL | 主机精确(引擎只按主机判范围,不看路径) |

"两段是域名、三段是主机"这条决定了授权范围,所以它必须能从写法上看出来 —— 想要
``a.b.x.com`` 整个范围就写 ``*.a.b.x.com``,不要指望它自己放宽。
"""

from __future__ import annotations

import ipaddress
import re
from typing import Dict, List, NamedTuple, Tuple
from urllib.parse import urlsplit

# 从网页、报告、聊天记录里粘过来的清单:逗号/分号/顿号/换行/空格都是分隔符
_SPLIT_RE = re.compile(r"[,;，；、\s]+")
# 夹在句子里、和中文粘在一起的 URL。到中日韩字符、全角标点就停 —— 否则
# "对https://x.com做信息收集" 会连中文一起吃进目标里(旧的 _URL_RE 就是这个毛病)
_URL_IN_TEXT_RE = re.compile(
    r"https?://[^\s<>\"'，。；）】、\u3000-\u303f\u4e00-\u9fff\uff00-\uffef]+", re.IGNORECASE
)
# 粘贴时常见的包裹(反引号、引号、尖括号、markdown 的方括号)
_TRIM_CHARS = "`'\"<>()[]{}_ \t\r\n"
# 强制放宽的写法,和 SurfaceScope 的 wildcard 约定一致(`_scope_host` 会剥掉 `*.`)
_WILDCARD_PREFIX = "*."
# 最后一段必须是"字母开头且至少两个字符",否则 "v1.2.3" 这种散文会被当成主机
_TLD_RE = re.compile(r"[a-z][a-z0-9-]+", re.IGNORECASE)

# 两段式公共后缀:不列出来,x.co.uk 会因为"三段"被误判成精确主机。
# 这张表换的是可预测性,所以宁小勿大 —— 漏掉的用 *.x.co.xx 显式写出来。
_TWO_LABEL_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "co.kr", "or.kr", "co.in", "co.za", "co.id", "co.nz", "co.il",
    "com.br", "com.mx", "com.ar", "com.tr", "com.tw", "com.hk", "com.sg", "com.pl",
})

MAX_ENTRIES = 200
MAX_REJECTED = 50


class TargetSplit(NamedTuple):
    """一次解析的结果。三个列表都已去重、排序 —— 顺序稳定才能有稳定 digest。"""

    entrypoints: Tuple[str, ...]      # 归一化后的 URL
    domains: Tuple[str, ...]          # 裸域名
    hosts: Tuple[str, ...]            # 裸精确主机
    rejected: Tuple[Tuple[str, str], ...]   # (原文, 原因)
    tokens: int = 0                   # 参与判定的 token 数(判定"清单还是散文"用)


class Asset(NamedTuple):
    """一个要单独跑的任务种子。"""

    kind: str        # entrypoint | domain | host
    host: str
    display: str     # 任务上显示的目标,也是 job.target

    @property
    def seed_url(self) -> str:
        return self.display


class Rejected(Exception):
    """这一条不能作为目标。``reason`` 是给操作员看的短标签。"""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def public_target_reason(raw: str) -> str:
    """公网 http(s) 目标才放行。返回 "" 表示通过,否则是拒绝原因。

    这是防越权 + SSRF 面的唯一闸门:内嵌凭据、畸形端口、localhost、
    私网/回环/链路本地/保留/组播地址、无点的裸主机名一律拒。
    ``console/deps.py`` 的 ``_valid_public_target`` 就是它的薄包装。
    """
    s = (raw or "").strip()
    if not s:
        return "empty"
    if len(s) > 300:
        return "too_long"
    if " " in s:
        return "whitespace"
    cand = s if "://" in s else "http://" + s
    try:
        u = urlsplit(cand)
    except Exception:  # noqa: BLE001 - 畸形输入一律拒,不向上抛
        return "unparsable"
    if u.scheme not in ("http", "https"):
        return "scheme_not_http"
    # 凭据和畸形端口绝不能进持久化的 intake 记录:除了防止顺手把密钥存下来,
    # 也让这里的判定和 SurfaceScope.check_url() 保持一致。
    if u.username or u.password:
        return "embedded_credentials"
    try:
        _ = u.port
    except ValueError:
        return "bad_port"
    host = (u.hostname or "").lower()
    if not host:
        return "missing_host"
    if not host.isascii():
        # 非 ASCII 主机名必须写成 punycode(浏览器粘出来的一定是 xn--)。这里不做
        # 转换:不做转换还放行,"10.0.0.5做" 这种粘了中文的地址就会绕开下面的
        # 私网判定(ipaddress 认不出来,又"有个点"),变成一条能真的发出去的请求。
        return "not_a_public_host"
    if host == "localhost" or host.endswith(".localhost"):
        return "localhost"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if "." not in host:                       # 非 IP 且无点 = 裸主机名
            return "not_a_public_host"
    else:
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified):
            return "non_public_ip"
    return ""


def _strip_decoration(token: str) -> str:
    """剥掉粘贴带进来的引号、反引号、尖括号、markdown 星号和结尾多余的斜杠。"""
    t = (token or "").strip().strip(_TRIM_CHARS)
    # markdown 强调(**x.com**)要剥,但 "*." 是通配符语法,不能一起吃掉
    while t.startswith("*") and not t.startswith(_WILDCARD_PREFIX):
        t = t[1:]
    while t.endswith("*"):
        t = t[:-1]
    while t.endswith("/"):
        stripped = t[:-1]
        after = stripped.split("://", 1)[1] if "://" in stripped else stripped
        if "/" in after:                          # 后面还有路径,那个斜杠是内容
            break
        t = stripped
    return t


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _tld_reason(host: str) -> str:
    """挡掉 "v1.2.3" 这类看着像主机其实不是的东西。"""
    if _is_ip(host):
        return ""
    labels = host.split(".")
    if len(labels) < 2:
        return "not_a_public_host"
    if not _TLD_RE.fullmatch(labels[-1]):
        return "not_a_tld"
    return ""


def _looks_targetish(token: str) -> bool:
    """只对"像目标"的 token 做判定并记录拒绝原因。

    粘一整页程序说明时,散落的散文词会被拆成一堆 token;把它们逐条报成
    "拒绝"只会把确认单淹掉。没有点、没有斜杠、没有 scheme 的,当散文忽略。
    """
    body = token[len(_WILDCARD_PREFIX):] if token.startswith(_WILDCARD_PREFIX) else token
    return "://" in body or "/" in body or "." in body


def _bare_host(body: str) -> str:
    reason = public_target_reason(body)
    if reason:
        raise Rejected(reason)
    host = (urlsplit(f"http://{body}").hostname or "").lower().rstrip(".")
    if not host:
        raise Rejected("missing_host")
    return host


def _entrypoint(token: str) -> Asset:
    reason = public_target_reason(token)
    if reason:
        raise Rejected(reason)
    parsed = urlsplit(token if "://" in token else f"https://{token}")
    host = (parsed.hostname or "").lower().rstrip(".")
    reason = _tld_reason(host)
    if reason:
        raise Rejected(reason)
    scheme = parsed.scheme.lower() if parsed.scheme.lower() in ("http", "https") else "https"
    port = f":{parsed.port}" if parsed.port is not None else ""
    tail = parsed.path or "/"
    if parsed.query:
        tail = f"{tail}?{parsed.query}"           # 片段不带,查询串是种子的一部分
    return Asset("entrypoint", host, f"{scheme}://{host}{port}{tail}")


def _looks_like_domain(host: str) -> bool:
    """剥掉公共后缀后只剩一段 = 这是注册域本身;否则是它的某个主机。

    所以 ``rei.com`` 和 ``b.co.uk`` 是域名,``www.rei.com`` 和 ``a.b.co.uk`` 是精确主机。
    想覆盖 ``a.b.co.uk`` 整片就写 ``*.a.b.co.uk`` —— 这条边界必须能从写法上看出来。
    """
    if _is_ip(host):
        return False
    labels = host.split(".")
    if len(labels) == 2:
        return True
    return len(labels) == 3 and ".".join(labels[-2:]) in _TWO_LABEL_SUFFIXES


def _classify(token: str) -> Asset:
    wildcard = token.startswith(_WILDCARD_PREFIX)
    if wildcard:
        body = token[len(_WILDCARD_PREFIX):]
        if "/" in body or ":" in body:
            raise Rejected("wildcard_not_a_host")
        if not body:
            raise Rejected("wildcard_only")
        host = _bare_host(body)
        reason = _tld_reason(host)
        if reason:
            raise Rejected(reason)
        return Asset("domain", host, f"https://{host}/")

    if "://" in token or "/" in token or ":" in token:
        return _entrypoint(token)

    host = _bare_host(token)
    reason = _tld_reason(host)
    if reason:
        raise Rejected(reason)
    return Asset("domain" if _looks_like_domain(host) else "host", host, f"https://{host}/")


def _covered_by_domain(host: str, domains: Tuple[str, ...]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def first_url(text: str) -> str:
    """文本里第一个 http(s) URL —— 和 ``split_targets`` 用同一套边界。

    旧的贪心正则 ``https?://[^\\s]+`` 会把粘在 URL 后面的中文一起吃进来
    (``对https://x.com做信息收集`` → ``https://x.com做信息收集``),而那种串在
    公网闸门那里是"有个点、不是 IP"所以放行的。取 URL 只能有一个地方。
    """
    match = _URL_IN_TEXT_RE.search(text or "")
    return _strip_decoration(match.group(0)) if match else ""


def split_targets(blob: str, *, max_entries: int = MAX_ENTRIES) -> TargetSplit:
    """把一段文本拆成三类目标。不可用的条目带原因进 ``rejected``。

    覆盖合并:如果同一个清单里既有 ``rei.com`` 又有 ``www.rei.com``,后者已经被前者
    授权了,再单开一个任务就是重复扫同一个资产 —— 所以丢掉并在 ``rejected`` 里注明。
    """
    entrypoints: List[str] = []
    domains: List[str] = []
    hosts: List[str] = []
    rejected: List[Tuple[str, str]] = []
    seen: set = set()

    text = blob or ""
    # 先摘出夹在句子里的 URL(它们可能和中文粘着),剩下的按分隔符切。
    # 摘掉的 URL 会从余下文本里移除,所以不会重复计数。
    embedded = [t for t in (_strip_decoration(u) for u in _URL_IN_TEXT_RE.findall(text)) if t]
    rest = [t for t in (_strip_decoration(p) for p in _SPLIT_RE.split(_URL_IN_TEXT_RE.sub(" ", text))) if t]
    # considered 是"这段文本里有多少个词",散文也算 —— 调用方靠它判断这是清单还是说明文字
    considered = len(embedded) + len(rest)

    for token in embedded + [t for t in rest if _looks_targetish(t)]:
        if len(entrypoints) + len(domains) + len(hosts) >= max_entries:
            if len(rejected) < MAX_REJECTED:
                rejected.append((token, "too_many"))
            continue
        try:
            asset = _classify(token)
        except Rejected as exc:
            if len(rejected) < MAX_REJECTED:
                rejected.append((token, exc.reason))
            continue
        key = (asset.kind, asset.host) if asset.kind != "entrypoint" else ("entrypoint", asset.display)
        if key in seen:
            continue
        seen.add(key)
        if asset.kind == "entrypoint":
            entrypoints.append(asset.display)
        elif asset.kind == "domain":
            domains.append(asset.host)
        else:
            hosts.append(asset.host)

    domain_set = tuple(sorted(set(domains)))
    kept_hosts: List[str] = []
    for host in sorted(set(hosts)):
        if _covered_by_domain(host, domain_set):
            rejected.append((host, "covered_by_domain"))
        else:
            kept_hosts.append(host)
    kept_entrypoints: List[str] = []
    for url in sorted(set(entrypoints)):
        host = (urlsplit(url).hostname or "").lower()
        if _covered_by_domain(host, domain_set):
            rejected.append((url, "covered_by_domain"))
        else:
            kept_entrypoints.append(url)

    return TargetSplit(
        entrypoints=tuple(kept_entrypoints),
        domains=domain_set,
        hosts=tuple(kept_hosts),
        rejected=tuple(rejected[:MAX_REJECTED]),
        tokens=considered,
    )


def assets(split: TargetSplit) -> Tuple[Asset, ...]:
    """解析结果 → 任务种子。入口 URL 排前面,它是比裸域名更好的起点。"""
    out: List[Asset] = [Asset("entrypoint", (urlsplit(u).hostname or "").lower(), u)
                        for u in split.entrypoints]
    out.extend(Asset("domain", d, f"https://{d}/") for d in split.domains)
    out.extend(Asset("host", h, f"https://{h}/") for h in split.hosts)
    return tuple(out)


def scope_lists(split: TargetSplit) -> Dict[str, List[str]]:
    """给 RouteDecision.scope / 预览记录用的三个列表。"""
    return {
        "entrypoints": list(split.entrypoints),
        "domains": list(split.domains),
        "hosts": list(split.hosts),
    }


__all__ = [
    "Asset", "MAX_ENTRIES", "Rejected", "TargetSplit",
    "assets", "first_url", "public_target_reason", "scope_lists", "split_targets",
]
