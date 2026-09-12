#!/usr/bin/env python3
"""SuccessCase 库（设计文档 §35）：成功漏洞的持久化 + 规则回放 + 联动删除。

- 永久存储、不脱敏（自用）；完整原始请求响应落盘。
- 规则收紧后用本库回放：**任一成功案例在新规则下不再命中 = 收紧回滚**。
- retract（翻案）不物理删除：移入 retracted/ + ledger 留痕 + 级联提示清单。

self-test：建两个案例 → 回放通过 → 收紧规则后回放检出丢失 → retract 联动清单。
"""
from __future__ import annotations

import json
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

# 案例回放命中判定：规则引擎对该案例的请求侧/响应侧至少一条命中即视为"仍识别"
@dataclass
class SuccessCase:
    case_id: str
    target: str
    vuln_type: str                    # sqli/xss/ssti/ssrf/rce/file_read/path_traversal/webshell...
    request: Dict[str, Any]           # {method,url,params,body}
    response: Dict[str, Any]          # {status,body,json?}
    evidence_refs: List[str] = field(default_factory=list)
    rule_ids: List[str] = field(default_factory=list)   # 当初命中链
    three_questions: Dict[str, str] = field(default_factory=dict)
    confirmed_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S"))
    note: str = ""


class SuccessCaseStore:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.cases_dir = self.root / "cases"
        self.retracted_dir = self.root / "retracted"
        self.ledger = self.root / "retraction_ledger.jsonl"
        self.cases_dir.mkdir(parents=True, exist_ok=True)
        self.retracted_dir.mkdir(parents=True, exist_ok=True)

    def _path(self, case_id: str) -> Path:
        return self.cases_dir / f"{case_id}.json"

    def add(self, case: SuccessCase) -> Path:
        path = self._path(case.case_id)
        path.write_text(json.dumps(case.__dict__, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    def load_all(self) -> List[SuccessCase]:
        out: List[SuccessCase] = []
        for p in sorted(self.cases_dir.glob("*.json")):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                out.append(SuccessCase(**data))
            except Exception:
                continue
        return out

    def replay(self, scanner) -> Dict[str, Any]:
        """用规则引擎回放全部案例。返回 {total, kept, lost:[case_id]}。
        判定：案例的请求/响应经扫描后仍至少命中一条规则 → kept，否则 lost。"""
        kept: List[str] = []
        lost: List[str] = []
        for case in self.load_all():
            req = case.request or {}
            resp = case.response or {}
            hits = scanner.scan_request(str(req.get("method") or "GET"),
                                        str(req.get("url") or ""),
                                        params=req.get("params") or {},
                                        body_text=str(req.get("body") or ""))
            hits += scanner.scan_response(str(req.get("method") or "GET"),
                                          str(req.get("url") or ""),
                                          body_text=str(resp.get("body") or ""),
                                          json_body=resp.get("json"))
            if hits:
                kept.append(case.case_id)
            else:
                lost.append(case.case_id)
        return {"total": len(kept) + len(lost), "kept": kept, "lost": lost}

    def retract(self, case_id: str, reason: str) -> Dict[str, Any]:
        """联动删除（§35 CaseRetraction）：移 retracted/ + ledger + 级联提示。"""
        src = self._path(case_id)
        if not src.exists():
            return {"ok": False, "error": f"case_not_found:{case_id}"}
        dst = self.retracted_dir / src.name
        shutil.move(str(src), str(dst))
        entry = {
            "case_id": case_id,
            "reason": reason,
            "retracted_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        with self.ledger.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        cascades = [
            "检查该案例支撑过的 finding/报告评级是否需降级或撤稿",
            "若该案例是某规则收紧决策的真阳性证据 → 该收紧动作必须重新评审",
            "若该案例是某 playbook/打法卡来源 → 对应卡片 source 标 retracted 并降级",
        ]
        return {"ok": True, "moved_to": str(dst), "ledger": str(self.ledger),
                "cascade_checklist": cascades}


def _self_test() -> int:
    import tempfile
    from rules_engine import TrafficRuleScanner
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from rules_engine import TrafficRuleScanner  # noqa

    with tempfile.TemporaryDirectory() as tmp:
        store = SuccessCaseStore(Path(tmp) / "success_cases")
        store.add(SuccessCase(
            case_id="SC-001", target="t1", vuln_type="sqli",
            request={"method": "POST", "url": "https://t/api/list",
                     "params": {"sortName": "id"}, "body": ""},
            response={"status": 200, "body": "", "json": {"data": {"sortName": "id"}}},
            rule_ids=["xiasql_order_field"]))
        store.add(SuccessCase(
            case_id="SC-002", target="t1", vuln_type="info_leak",
            request={"method": "GET", "url": "https://t/api/cfg", "params": {}, "body": ""},
            response={"status": 200, "body": '{"access_key":"LTAI4G8fakevalue123456"}', "json": None},
            rule_ids=["hae_cloud_aksk"]))

        rules_dir = Path(__file__).resolve().parent.parent / "references" / "traffic-rules"
        scanner = TrafficRuleScanner(rules_dir)
        result = store.replay(scanner)
        assert result["total"] == 2 and not result["lost"], result

        # 收紧模拟：删掉所有规则 → 回放必须检出丢失
        empty_dir = Path(tmp) / "empty_rules"
        empty_dir.mkdir()
        (empty_dir / "empty.yaml").write_text("schema: TrafficRuleSet/v1\nrule_set: empty\nrules: []\n", encoding="utf-8")
        tight = TrafficRuleScanner(empty_dir)
        result2 = store.replay(tight)
        assert result2["lost"] == ["SC-001", "SC-002"], result2

        # retract 联动
        out = store.retract("SC-001", "复核翻案：证据链断裂")
        assert out["ok"] and len(out["cascade_checklist"]) == 3
        assert not store._path("SC-001").exists()
        assert (store.retracted_dir / "SC-001.json").exists()
        assert store.ledger.read_text(encoding="utf-8").strip()
        result3 = store.replay(scanner)
        assert result3["total"] == 1, result3

    print("success_cases self-test ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())
