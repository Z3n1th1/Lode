#!/usr/bin/env python3
"""Verifier 对抗复核角色（设计文档 §13：执行者≠审查者，证据>叙事）。

本模块是复核的**确定性判定框架**（LLM 复核由 agent 角色在此框架内调用）：
客观校验三问是否书面回答、归属问是否有对照证据、severity 与证据是否匹配、
证据文件是否真实存在。任一不满足 → rejected / needs_more_evidence，绝不放行。

来源：复盘实证（F-07 无对照证据定 High、F-04 职责内功能当漏洞）+
提示词库"项目复盘与技术审计专家"（不得仅凭文字标记判定完成）。

self-test：构造通过/拒绝/补证三态 finding，验证判定。
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

THREE_QUESTION_MARKERS = ("绕过", "归属", "设计")
HIGH_SEVERITIES = {"high", "critical"}
COUNTED_SEVERITIES = {"medium", "high", "critical"}


@dataclass
class VerifierResult:
    status: str                    # confirmed | rejected | needs_more_evidence
    finding_id: str
    reasons: List[str] = field(default_factory=list)
    checked_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S"))
    severity_cap: Optional[str] = None   # 证据不足时的评级上限（如 low）


def verify_finding_draft(finding: Dict[str, Any], *, project_root: Optional[Path] = None) -> VerifierResult:
    """对 finding 草稿做对抗复核。

    finding 需要的键：
      id/severity/title/three_questions{绕过,归属,设计}/
      evidence_refs[](路径或 pair_id)/control_evidence(High 必需的对照证据引用)
    """
    fid = str(finding.get("id") or finding.get("finding_id") or "?")
    severity = str(finding.get("severity") or "").lower()
    reasons: List[str] = []

    # 1. 三问书面回答检查（对抗点：空泛/敷衍回答视为未回答；短但有内容的答案不误伤）
    PERFUNCTORY = {"", "无", "略", "不知道", "不清楚", "none", "n/a", "na", "没有"}
    tq = finding.get("three_questions") or {}
    if isinstance(tq, dict):
        for q in THREE_QUESTION_MARKERS:
            ans = str(tq.get(q) or "").strip()
            if len(ans) < 4 or ans.lower() in PERFUNCTORY:
                reasons.append(f"three_questions:{q}问未书面回答或过于敷衍")
    else:
        text = str(tq)
        for q in THREE_QUESTION_MARKERS:
            if q not in text:
                reasons.append(f"three_questions:缺{q}问")

    # 2. 归属问必须有对照材料（对抗点：口头声称"已对照"不算）
    tq_dict = tq if isinstance(tq, dict) else {}
    belongs_ans = str(tq_dict.get("归属") or "")
    if belongs_ans and not any(k in belongs_ans for k in ("对照", "A/B", "正常应", "不应", "职责内")):
        reasons.append("belonging:归属问未给出'正常应允许/不应允许/实际拿到'的对照结构")

    # 3. 证据存在性（对抗点：引用了不存在的证据）
    evidence_refs = finding.get("evidence_refs") or []
    if severity in COUNTED_SEVERITIES and not evidence_refs:
        reasons.append("evidence:medium+ finding 无任何 evidence_refs")
    if project_root is not None:
        for ref in evidence_refs:
            ref_path = Path(str(ref).split("#")[0])
            if not ref_path.is_absolute():
                ref_path = Path(project_root) / ref_path
            if not ref_path.exists():
                reasons.append(f"evidence:引用不存在 {ref}")

    # 4. High/Critical 必须有对照证据（F-07 教训）
    severity_cap: Optional[str] = None
    if severity in HIGH_SEVERITIES:
        control = finding.get("control_evidence")
        if not control:
            reasons.append("control:high/critical 缺 control_evidence（A/B 或有/无凭证对照）")
            severity_cap = "low"

    # 判定：rejected 是终态拒绝，不再设 severity_cap（cap 只用于"可留但降级"）
    hard_fail = [r for r in reasons if r.startswith("three_questions") or r.startswith("evidence")]
    if hard_fail:
        return VerifierResult(status="rejected", finding_id=fid, reasons=reasons, severity_cap=None)
    if reasons:
        return VerifierResult(status="needs_more_evidence", finding_id=fid, reasons=reasons,
                              severity_cap=severity_cap)
    return VerifierResult(status="confirmed", finding_id=fid, reasons=[], severity_cap=None)


def _self_test() -> int:
    good = {
        "id": "F-01", "severity": "medium",
        "three_questions": {
            "绕过": "绕过前端扩展名校验，服务端未二次校验（改包采信）",
            "归属": "正常应允许读自己订单；不应允许读他人订单；实际拿到他人订单详情（A/B 对照）",
            "设计": "不能被设计解释：低权角色不应可读他人对象",
        },
        "evidence_refs": ["evidence/t1/raw/FIND-001/request.http"],
    }
    r = verify_finding_draft(good)
    assert r.status in ("confirmed", "needs_more_evidence"), r  # 无 project_root 不查文件存在性

    bad = {"id": "F-02", "severity": "high", "three_questions": {"绕过": "无", "归属": "拿到了数据", "设计": ""},
           "evidence_refs": []}
    r2 = verify_finding_draft(bad)
    assert r2.status == "rejected" and r2.severity_cap is None, r2

    no_control = {
        "id": "F-03", "severity": "high",
        "three_questions": {
            "绕过": "删除凭证头后仍返回数据，绕过认证",
            "归属": "正常应允许读自己数据；正常不应允许匿名读；实际匿名拿到真实业务数据（有无凭证对照）",
            "设计": "不能被设计解释",
        },
        "evidence_refs": ["evidence/t1/raw/FIND-003/request.http"],
    }
    r3 = verify_finding_draft(no_control)
    assert r3.status == "needs_more_evidence" and r3.severity_cap == "low", r3

    print("verifier_agent self-test ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())
