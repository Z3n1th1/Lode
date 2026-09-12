#!/usr/bin/env python3
"""TrafficRuleScanner 引擎（设计文档 §31）：一切流量的被动规则匹配层。

核心纪律：
- 命中产出 PassiveHit（线索），永远不是漏洞结论；升级路径只有"带证据过三问门"。
- 规则即数据（references/traffic-rules/*.yaml），热更新，不进 core。
- 归一化先行：参数名去非字母数字+小写（sort_name/sortName/sort-name 归一），
  值侧多轮 percent-decode（与 action_policy 的 I4 修复同源经验）。
- 置信度：hint（仅记录）→ candidate（进 HighValueQueue）→ urgent（P0 通知）；
  提升靠"请求侧命中 + 响应侧确认配对"与"值格式分级"，不靠单条正则拍板。

self-test：加载本仓库 traffic-rules 两份规则，对模拟流量验证命中、归一化、
确认配对升级、urgent 判定。
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import parse_qsl, unquote, urlsplit

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None


@dataclass
class PassiveHit:
    rule_id: str
    category: str
    priority: str
    endpoint: str
    param: Optional[str] = None
    matched_text: str = ""
    confidence: str = "hint"          # hint | candidate | urgent
    rationale: str = ""
    created_at: str = ""


def _normalize(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (name or "").lower())


def _decode_variants(val: str, rounds: int = 3) -> List[str]:
    variants = [val]
    cur = val
    for _ in range(rounds):
        nxt = unquote(cur)
        if nxt == cur:
            break
        variants.append(nxt)
        cur = nxt
    return variants


class Rule:
    def __init__(self, raw: Dict[str, Any], rule_set: str) -> None:
        self.rule_set = rule_set
        self.id = str(raw.get("id"))
        self.category = str(raw.get("category") or "")
        self.priority = str(raw.get("priority") or "P1")
        self.match = raw.get("match") or {}
        self.suggested_action = str(raw.get("suggested_action") or "")
        self.rationale = str(raw.get("rationale") or "")
        mtype = str(self.match.get("type") or "")
        if mtype == "body_regex":
            self._regex = re.compile(str(self.match.get("pattern") or ""), re.I)
        elif mtype == "response_json_key":
            self._regex = re.compile(str(self.match.get("key_pattern") or ""), re.I)
        else:
            self._regex = None

    def match_param(self, param_name: str) -> bool:
        if str(self.match.get("type") or "") != "param_name_normalized":
            return False
        norm = _normalize(param_name)
        m = self.match
        if norm in {_normalize(x) for x in m.get("exact") or []}:
            return True
        if any(norm.startswith(_normalize(x)) for x in m.get("prefix") or []):
            return True
        if any(norm.endswith(_normalize(x)) for x in m.get("ends_with") or []):
            return True
        if any(_normalize(x) in norm for x in m.get("contains") or []):
            return True
        raw_l = (param_name or "").lower()
        if any(raw_l.endswith(str(s).lower()) for s in m.get("suffix") or []):
            return True
        return False

    def match_body(self, text: str) -> Optional[str]:
        if self._regex is None or str(self.match.get("type") or "") != "body_regex":
            return None
        for variant in _decode_variants(text):
            m = self._regex.search(variant)
            if m:
                return m.group(0)[:200]
        return None

    def match_response_key(self, key_path: str) -> bool:
        if str(self.match.get("type") or "") != "response_json_key":
            return False
        if self._regex is not None and self._regex.search(key_path or ""):
            return True
        # 归一化兜底：sortVal/orderBy 等驼峰粘连键，整词正则失配（I2 同源经验）
        norm_table = self.match.get("normalized_keys")
        if norm_table:
            leaf = str(key_path or "").split(".")[-1]
            leaf = re.sub(r"\[\d+\]", "", leaf)
            if _normalize(leaf) in {_normalize(str(x)) for x in norm_table}:
                return True
        return False


class TrafficRuleScanner:
    def __init__(self, rules_dir: Path) -> None:
        if yaml is None:
            raise RuntimeError("pyyaml_unavailable")
        self.rules: List[Rule] = []
        self._load(rules_dir)

    def _load(self, rules_dir: Path) -> None:
        for path in sorted(Path(rules_dir).glob("*.yaml")):
            doc = yaml.safe_load(path.read_text(encoding="utf-8-sig")) or {}
            if not isinstance(doc, dict):
                continue
            rule_set = str(doc.get("rule_set") or path.stem)
            for raw in doc.get("rules") or []:
                if isinstance(raw, dict) and raw.get("id"):
                    self.rules.append(Rule(raw, rule_set))

    @staticmethod
    def _iter_json_keys(obj: Any, prefix: str = "") -> Iterable[str]:
        if isinstance(obj, dict):
            for k, v in obj.items():
                path = f"{prefix}.{k}" if prefix else str(k)
                yield path
                yield from TrafficRuleScanner._iter_json_keys(v, path)
        elif isinstance(obj, list):
            for i, v in enumerate(obj[:50]):
                yield from TrafficRuleScanner._iter_json_keys(v, f"{prefix}[{i}]")

    def scan_request(self, method: str, url: str, *,
                     params: Optional[Dict[str, Any]] = None,
                     body_text: str = "") -> List[PassiveHit]:
        endpoint = f"{method.upper()} {urlsplit(url).path or url}"
        hits: List[PassiveHit] = []
        all_params: Dict[str, Any] = dict(params or {})
        for k, v in parse_qsl(urlsplit(url).query):
            all_params.setdefault(k, v)
        for rule in self.rules:
            for name in all_params:
                if rule.match_param(str(name)):
                    hits.append(PassiveHit(rule.id, rule.category, rule.priority, endpoint,
                                           param=str(name), rationale=rule.rationale,
                                           created_at=time.strftime("%Y-%m-%dT%H:%M:%S")))
            if body_text:
                matched = rule.match_body(body_text)
                if matched is not None and rule.category != "sqli_orderby_confirm":
                    hits.append(PassiveHit(rule.id, rule.category, rule.priority, endpoint,
                                           matched_text=matched, rationale=rule.rationale,
                                           created_at=time.strftime("%Y-%m-%dT%H:%M:%S")))
        return hits

    def scan_response(self, method: str, url: str, *,
                      body_text: str = "", json_body: Any = None) -> List[PassiveHit]:
        endpoint = f"{method.upper()} {urlsplit(url).path or url}"
        hits: List[PassiveHit] = []
        for rule in self.rules:
            if body_text:
                matched = rule.match_body(body_text)
                if matched is not None:
                    hits.append(PassiveHit(rule.id, rule.category, rule.priority, endpoint,
                                           matched_text=matched, rationale=rule.rationale,
                                           created_at=time.strftime("%Y-%m-%dT%H:%M:%S")))
            if json_body is not None and str(rule.match.get("type") or "") == "response_json_key":
                for key_path in self._iter_json_keys(json_body):
                    if rule.match_response_key(key_path):
                        hits.append(PassiveHit(rule.id, rule.category, rule.priority, endpoint,
                                               matched_text=key_path, rationale=rule.rationale,
                                               created_at=time.strftime("%Y-%m-%dT%H:%M:%S")))
                        break
        return hits

    @staticmethod
    def apply_confidence(req_hits: List[PassiveHit], resp_hits: List[PassiveHit],
                         *, param_values: Optional[Dict[str, str]] = None) -> List[PassiveHit]:
        """置信度提升：请求侧命中 + 同端点响应侧确认 → candidate；
        值格式高危（纯字段名/列号/字段+方向一体）→ urgent。"""
        confirmed_endpoints = {h.endpoint for h in resp_hits
                               if h.category.endswith("_confirm") or h.category in ("credential", "debug_leak")}
        out: List[PassiveHit] = []
        for hit in req_hits:
            h = PassiveHit(**hit.__dict__)
            if h.endpoint in confirmed_endpoints:
                h.confidence = "candidate"
                if h.param and param_values:
                    v = (param_values.get(h.param) or "").strip()
                    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(\s+(asc|desc))?", v, re.I) or v.isdigit():
                        h.confidence = "urgent"
            elif h.category == "credential" and h.matched_text:
                h.confidence = "urgent"
            out.append(h)
        # 响应侧凭据命中（非占位/示例）同样升 urgent——凭据泄露主要在响应里
        for hit in resp_hits:
            if hit.category == "credential" and hit.matched_text and hit.confidence == "hint":
                hit.confidence = "urgent"
        out.extend(resp_hits)
        return out


def _self_test() -> int:
    rules_dir = Path(__file__).resolve().parent.parent / "references" / "traffic-rules"
    scanner = TrafficRuleScanner(rules_dir)
    assert len(scanner.rules) >= 8, f"规则加载过少: {len(scanner.rules)}"

    # 1. 归一化命中：sortName / sort_name / sort-name 应归一命中同一规则
    for variant in ("sortName", "sort_name", "sort-name", "sortBy"):
        hits = scanner.scan_request("POST", "https://t/api/list", params={variant: "asc"})
        assert any(h.rule_id == "xiasql_order_field" for h in hits), (variant, hits)

    # 2. 方向参数 + 值格式高危 → 配响应确认后 urgent
    req = scanner.scan_request("POST", "https://t/api/game/list", params={"sortVal": "createTime desc"})
    resp = scanner.scan_response("POST", "https://t/api/game/list",
                                 json_body={"data": {"list": [], "sortVal": "createTime desc"}})
    merged = TrafficRuleScanner.apply_confidence(req, resp,
                                                 param_values={"sortVal": "createTime desc"})
    urgent = [h for h in merged if h.confidence == "urgent"]
    assert urgent, [ (h.rule_id, h.confidence) for h in merged ]

    # 3. 凭据命中 → urgent（无需配对）
    cred = scanner.scan_response("GET", "https://t/api/cfg", body_text='{"access_key":"LTAI4G8fakesecretkeyvalue123"}')
    assert any(h.rule_id == "hae_cloud_aksk" for h in cred), cred
    cred2 = TrafficRuleScanner.apply_confidence([], cred)
    assert any(h.confidence == "urgent" for h in cred2), cred2

    # 4. 非相关参数不误报
    none_hits = scanner.scan_request("GET", "https://t/api/user/info", params={"name": "abc", "page": "1"})
    assert not [h for h in none_hits if h.rule_id.startswith("xiasql_order")], none_hits

    # 5. URL 编码的响应体也能命中（多轮 decode）
    enc = scanner.scan_response("GET", "https://t/api/x", body_text="key%3D%22AKIAIOSFODNN7EXAMPLE%22")
    assert any(h.rule_id == "hae_cloud_aksk" for h in enc), enc

    print(f"rules_engine self-test ok ({len(scanner.rules)} rules)")
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())
