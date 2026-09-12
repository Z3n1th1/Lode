#!/usr/bin/env python3
"""RuleAuditor：误报治理闭环（设计文档 §31.2）。

核心思想（用户拍板）：**降误报不靠砍规则/少报（牺牲覆盖），靠审计整条路线找判定链的错。**
线索层保持贪婪（全面），结论层保持苛刻（精准），RuleAuditor 持续校准。

三段职责：
1. detect_fp_signals：从命中日志/判定记录计算每条规则的转化率/驳回率，超阈产出
   FalsePositiveSignal（确定性，脚本判，不靠模型感觉）。
2. build_audit_prompt：组装给高级模型的路线审计输入（规则文本 + 命中样本 + 判定/Verifier
   结论），产出结构化 prompt；审计结论落 RouteAuditCard。
3. verify_tightening：收紧后的规则变更必须用 SuccessCase 全量回放——任一成功案例
   不再命中 = 收紧回滚（能力不降的硬执行）。

self-test：构造命中日志 → 信号触发 → prompt 组装 → 回放验证。
"""
from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class RuleStats:
    rule_id: str
    hits: int = 0
    confirmed: int = 0
    rejected: int = 0
    candidate_stalled: int = 0     # 停在 candidate 无进展


@dataclass
class FalsePositiveSignal:
    rule_id: str
    reason: str
    conversion_rate: float
    rejection_rate: float
    sample_size: int
    detected_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S"))


# 阈值初值（设计文档 §33-18，跑两周按数据调）
MIN_SAMPLE = 10
MAX_CONVERSION = 0.05      # 命中→confirmed 转化率低于 5%
MAX_REJECTION = 0.30       # Verifier/人工驳回率高于 30%


def detect_fp_signals(stats: List[RuleStats], *,
                      min_sample: int = MIN_SAMPLE,
                      max_conversion: float = MAX_CONVERSION,
                      max_rejection: float = MAX_REJECTION) -> List[FalsePositiveSignal]:
    signals: List[FalsePositiveSignal] = []
    for s in stats:
        if s.hits < min_sample:
            continue
        conversion = s.confirmed / s.hits
        rejection = s.rejected / s.hits
        if conversion < max_conversion:
            signals.append(FalsePositiveSignal(s.rule_id, "low_conversion", conversion, rejection, s.hits))
        elif rejection > max_rejection:
            signals.append(FalsePositiveSignal(s.rule_id, "high_rejection", conversion, rejection, s.hits))
    return signals


def build_audit_prompt(rule_text: str, samples: List[Dict[str, Any]], signal: FalsePositiveSignal) -> str:
    """组装路线审计 prompt（给高级模型/独立会话）。审计整条链，不是单条。"""
    sample_lines = []
    for i, s in enumerate(samples[:20], 1):
        sample_lines.append(
            f"样本{i}: endpoint={s.get('endpoint')} param={s.get('param')} "
            f"matched={str(s.get('matched_text'))[:80]} 判定={s.get('verdict')} 证据={s.get('evidence', '无')}")
    return f"""# RuleAuditor 路线审计任务（独立审查，不得与执行者同模型）

## 被审计规则
rule_id: {signal.rule_id}
触发信号: {signal.reason}（转化率 {signal.conversion_rate:.1%} / 驳回率 {signal.rejection_rate:.1%} / 样本 {signal.sample_size}）
规则文本:
{rule_text}

## 命中样本（含后续判定与证据）
{chr(10).join(sample_lines) if sample_lines else '（无样本）'}

## 审计任务（审路线，不是审单条）
1. 根因分类（三选一）：规则太宽（贪匹配）/ 判定太松（无证据升级）/ 证据链断（有命中无验证路径）
2. 收紧建议（必须保真阳性）：加排除项？加置信度条件（命中+响应真实数据才升级）？降级为 hint？
3. 预测收紧后对历史成功案例的影响（会不会误伤已确认的真漏洞）
4. 输出 RouteAuditCard：{{rule_id, root_cause, tighten_actions[], predicted_true_positive_risk, confidence}}

纪律：不得仅凭文字标记判定完成；每条建议必须能指出样本中的证据。结论需接受人工抽审。
"""


@dataclass
class RouteAuditCard:
    rule_id: str
    root_cause: str               # rule_too_broad | loose_verdict | evidence_chain_broken
    tighten_actions: List[str]
    predicted_true_positive_risk: str = ""
    confidence: str = "medium"
    created_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S"))


def verify_tightening(success_store, new_rules_dir: Path) -> Dict[str, Any]:
    """收紧验证（硬约束）：SuccessCase 全量回放，丢一个真阳性 = 收紧回滚。"""
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "core"))
    from rules_engine import TrafficRuleScanner  # noqa
    scanner = TrafficRuleScanner(new_rules_dir)
    result = success_store.replay(scanner)
    result["rollback_required"] = bool(result["lost"])
    if result["lost"]:
        result["message"] = f"收紧导致成功案例丢失 {result['lost']}，必须回滚或修订规则"
    else:
        result["message"] = "回放全保留，收紧可生效"
    return result


def _self_test() -> int:
    # 1. 信号检测
    stats = [
        RuleStats("noisy_rule", hits=100, confirmed=1, rejected=50),
        RuleStats("good_rule", hits=50, confirmed=10, rejected=2),
        RuleStats("tiny_sample", hits=3, confirmed=0, rejected=3),   # 样本不足不触发
    ]
    signals = detect_fp_signals(stats)
    assert len(signals) == 1 and signals[0].rule_id == "noisy_rule", signals

    # 2. prompt 组装
    prompt = build_audit_prompt("pattern: sort|order", [{"endpoint": "GET /a", "param": "sort",
                                                         "matched_text": "sort", "verdict": "rejected"}],
                                signals[0])
    assert "路线审计" in prompt and "noisy_rule" in prompt and "根因分类" in prompt

    # 3. 收紧回放验证（用 success_cases 的临时库）
    import tempfile
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "core"))
    from success_cases import SuccessCase, SuccessCaseStore
    with tempfile.TemporaryDirectory() as tmp:
        store = SuccessCaseStore(Path(tmp) / "sc")
        store.add(SuccessCase(case_id="SC-1", target="t", vuln_type="sqli",
                              request={"method": "GET", "url": "https://t/a", "params": {"sortName": "id"}, "body": ""},
                              response={"status": 200, "body": "", "json": None}))
        # 3a. 规则保留 → 通过
        good_dir = Path(tmp) / "rules_ok"
        good_dir.mkdir()
        (good_dir / "r.yaml").write_text(
            "schema: TrafficRuleSet/v1\nrule_set: t\nrules:\n- id: keep_sort\n  category: c\n  priority: P0\n"
            "  match:\n    type: param_name_normalized\n    exact: [sortname]\n", encoding="utf-8")
        ok_result = verify_tightening(store, good_dir)
        assert not ok_result["rollback_required"], ok_result
        # 3b. 规则被砍 → 回滚
        bad_dir = Path(tmp) / "rules_bad"
        bad_dir.mkdir()
        (bad_dir / "r.yaml").write_text("schema: TrafficRuleSet/v1\nrule_set: t\nrules: []\n", encoding="utf-8")
        bad_result = verify_tightening(store, bad_dir)
        assert bad_result["rollback_required"] and "SC-1" in bad_result["lost"], bad_result

    print("rule_auditor self-test ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())
