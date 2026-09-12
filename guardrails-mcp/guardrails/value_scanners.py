"""Deterministic body/value scanners (red-team add-abuse-3/4/5).

These read the ActionCard's endpoint + request keys/values ONLY — never an
agent-authored "benign"/"intent" field. Any hit forces the human gate, so a
prompt-injected agent cannot label a create-admin / register-webhook /
capture-payment as "benign QA seed" and slip it past.

Hardening (2026-08-07 audit, findings H1-2/H1-3):
- ALL request containers are scanned (body/json/params/data/form/payload)
  plus the URL query string. Previously only the FIRST non-empty container
  was scanned, so a callback_url smuggled in `params` escaped detection and
  an allowlisted "inert" create could silently register a server-side egress.
- Endpoint text is matched in both raw and URL-decoded form so percent-encoded
  CJK paths cannot hide action/payment semantics.
- Hint vocabulary covers English + Chinese + common pinyin: the targets are
  Chinese-language surfaces, so an English-only lexicon is a bypass lane.
  All scanners are fail-safe: extra hits only ever RAISE to the human gate.
"""
from __future__ import annotations

import re
import urllib.parse
from typing import Any, Iterator, List, Mapping, Tuple

# key/value substrings that mean the create registers a SERVER-SIDE outbound
# (SSRF / exfil / C2) — egress that originates on the target, outside our netns.
_URL_KEY_HINTS = ("url", "uri", "callback", "webhook", "redirect", "notify",
                  "endpoint", "host", "fetch", "proxy", "avatar", "image_url",
                  "return_url", "notify_url", "link", "src",
                  # zh / pinyin
                  "回调", "通知地址", "跳转", "链接", "域名", "头像",
                  "huidiao", "tiaozhuan", "lianjie", "yuming", "touxiang")
_URL_VALUE_RE = re.compile(r"(?i)\b(?:https?|ftp|gopher|file|dict|ldap)://")
_HOSTISH_RE = re.compile(r"(?i)\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[a-z0-9-]+\.[a-z]{2,}\b")

# privilege / credential creation — the body distinguishes these, not the verb.
_PRIV_KEY_HINTS = ("role", "roles", "permission", "perm", "admin", "is_admin",
                   "is_staff", "is_superuser", "scope", "scopes", "grant",
                   "privilege", "token", "apikey", "api_key", "secret",
                   "client_secret", "access_level", "authority",
                   # zh / pinyin
                   "角色", "权限", "管理员", "超管", "授权", "凭证", "令牌", "密钥",
                   "juese", "quanxian", "guanliyuan", "chaoguan", "shouquan",
                   "pingzheng", "lingpai", "miyao")
# NOTE: '*'/'all'/'owner' removed — as bare values they are common benign
# filter/scope values (filter=all, q=*) and produced pervasive false-need_human.
# role=admin is still caught via the priv KEY ('role') below; strong value tokens
# (admin/root/superuser) stay.
_PRIV_VALUE_HINTS = ("admin", "root", "superuser",
                     "管理员", "超管", "超级管理员", "guanliyuan", "chaoguan")
# anti-CSRF form fields carry the word 'token' but are NOT credential issuance;
# excluding them stops csrf_token/_token from force-gating every real form POST.
_ANTI_CSRF_HINTS = ("csrf", "xsrf", "authenticity")
_PRIV_ENDPOINT_RE = re.compile(
    r"(?i)(sign[-_]?up|register|/users?\b|/invite|/members?\b|"
    r"/api[-_]?keys?\b|/tokens?\b|/oauth|/grant|/roles?\b|/permissions?\b|"
    r"/admins?\b|/guanli\b|/quanxian\b|/juese\b)")

# MUST-CLEANUP / irreversible side-effect surfaces (align with
# state_change_cleanup_gate). Creating these is the harm, not a cleanable row.
_CLEANUP_HINTS = ("order", "pay", "payment", "refund", "sms", "email", "mail",
                  "notify", "bind", "unbind", "coupon", "redeem", "voucher",
                  "withdraw", "transfer", "invite", "message", "send", "otp",
                  "verifycode", "captcha", "recharge", "settle",
                  # zh
                  "订单", "支付", "退款", "短信", "邮件", "通知", "绑定", "解绑",
                  "优惠券", "兑换", "提现", "转账", "邀请", "消息", "发送",
                  "验证码", "充值", "结算", "下单", "代金",
                  # pinyin
                  "dingdan", "zhifu", "tuikuan", "duanxin", "youjian",
                  "tongzhi", "bangding", "jiebang", "duihuan", "tixian",
                  "zhuanzhang", "yaoqing", "xiaoxi", "fasong", "yanzhengma",
                  "chongzhi", "jiesuan", "xiadan")

# shared / linked state — mutating it damages resources the id-ledger never sees.
_SHARED_HINTS = ("inventory", "stock", "balance", "wallet", "quota", "coupon",
                 "refund", "group", "tenant", "org", "team", "config", "setting",
                 "settings", "policy", "role", "member", "shared", "global",
                 # zh / pinyin
                 "库存", "余额", "钱包", "配额", "配置", "设置", "成员", "群组",
                 "租户", "全局",
                 "kucun", "qianbao", "peie", "peizhi", "shezhi", "chengyuan",
                 "qunzu", "zuhu", "quanju")


def _flatten(obj: Any, keys: List[str], values: List[str]) -> None:
    if isinstance(obj, Mapping):
        for k, v in obj.items():
            keys.append(str(k).lower())
            _flatten(v, keys, values)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _flatten(v, keys, values)
    elif obj is not None and not isinstance(obj, bool):
        values.append(str(obj))


def _containers(action: Mapping[str, Any]) -> Iterator[Any]:
    """Yield EVERY request container — never just the first non-empty one —
    plus the URL query string (all are attacker-controlled input surface).

    2026-08-07 review I5：query 逐字段解析——旧实现 `url or target` 短路，
    url 无 "?" 时 target 上的 callback_url 走私会被漏检。"""
    for k in ("body", "json", "params", "data", "form", "payload"):
        v = action.get(k)
        if v is not None:
            yield v
    for field in ("url", "target", "path", "endpoint"):
        val = str(action.get(field) or "")
        if "?" not in val:
            continue
        try:
            query = urllib.parse.urlsplit(val).query
        except Exception:
            continue
        if query:
            yield dict(urllib.parse.parse_qsl(query, keep_blank_values=True))


def _endpoint_text(action: Mapping[str, Any]) -> str:
    """Endpoint haystack in raw + repeatedly URL-decoded forms.

    Multi-round decoding (bounded at 3): framework/proxy combos that decode
    more than once must not let a double-encoded action/payment path hide.
    """
    raw = " ".join(str(action.get(k) or "") for k in ("url", "target", "path", "endpoint")).lower()
    parts = [raw]
    cur = raw
    for _ in range(3):
        try:
            nxt = urllib.parse.unquote(cur)
        except Exception:
            break
        if nxt == cur:
            break
        parts.append(nxt)
        cur = nxt
    return " ".join(parts)


def _parts(action: Mapping[str, Any]) -> Tuple[List[str], List[str], str]:
    keys: List[str] = []
    values: List[str] = []
    for container in _containers(action):
        _flatten(container, keys, values)
    return keys, values, _endpoint_text(action)


def has_url_or_callback_value(action: Mapping[str, Any]) -> bool:
    keys, values, _ = _parts(action)
    if any(any(h in k for h in _URL_KEY_HINTS) for k in keys):
        # only trip if a url-key actually carries a host/url-looking value,
        # OR the key name itself is an unambiguous callback/webhook/redirect
        for k in keys:
            if any(h in k for h in ("callback", "webhook", "redirect", "notify", "proxy", "fetch",
                                    "回调", "huidiao", "tiaozhuan")):
                return True
    for v in values:
        if _URL_VALUE_RE.search(v):
            return True
    # a url-key + a host-looking value
    if any(any(h in k for h in _URL_KEY_HINTS) for k in keys) and any(_HOSTISH_RE.search(v) for v in values):
        return True
    return False


def has_privilege_or_credential(action: Mapping[str, Any]) -> bool:
    keys, values, endpoint = _parts(action)
    if _PRIV_ENDPOINT_RE.search(endpoint):
        return True
    for k in keys:
        if any(x in k for x in _ANTI_CSRF_HINTS):
            continue  # csrf_token / xsrf / authenticity_token are not credentials
        if any(h == k or h in k for h in _PRIV_KEY_HINTS):
            return True
    low_values = [v.lower() for v in values]
    if any(pv in low_values for pv in _PRIV_VALUE_HINTS):
        return True
    return False


def has_cleanup_keyword(action: Mapping[str, Any]) -> bool:
    keys, values, endpoint = _parts(action)
    hay = " ".join([endpoint] + keys + [v.lower() for v in values])
    return any(h in hay for h in _CLEANUP_HINTS)


def touches_shared_state(action: Mapping[str, Any]) -> bool:
    keys, values, endpoint = _parts(action)
    hay = " ".join([endpoint] + keys + [v.lower() for v in values])
    return any(h in hay for h in _SHARED_HINTS)


def scan(action: Mapping[str, Any]) -> dict:
    """One-shot scan result used by action_policy."""
    return {
        "url_or_callback": has_url_or_callback_value(action),
        "privilege_or_credential": has_privilege_or_credential(action),
        "cleanup_keyword": has_cleanup_keyword(action),
        "shared_state": touches_shared_state(action),
    }