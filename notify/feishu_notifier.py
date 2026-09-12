#!/usr/bin/env python3
"""飞书播报骨架（Notifier 渠道适配，单向只出不进）。

纪律（设计文档 §19/§20）：
- 只发"结论 + 证据指针 + 需要你做什么"，**不发证据细节/凭据/请求响应**（渠道过第三方）。
- 分级节流：P0 立即（confirmed 中危+ / 碰墙升级 / 红线触发）；P1 阶段收口；P2 定时摘报。
- 审批回路不在此通道：飞书只用于通知，人工门批准必须回 mesh 内 WebUI。

配置（env，不进代码）：
  FEISHU_WEBHOOK   自定义机器人 webhook URL（https://open.feishu.cn/open-apis/bot/v2/hook/<token>）
  FEISHU_SECRET    可选，机器人签名校验 secret
  NOTIFY_QUIET_HOURS 可选，如 "23:00-08:00"（P0 仍会发，P1/P2 合并到摘报）

用法：
  python feishu_notifier.py --self-test
  python feishu_notifier.py --level P0 --title " confirmed: ThinkPHP debug 泄露配置" --body "证据 evidence/<id>；需要你：确认是否提交" --target t1
  作为库：from feishu_notifier import notify; notify(NotifyEvent(...))
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

_CORE_DIR = Path(__file__).resolve().parents[1] / "core"
if str(_CORE_DIR) not in sys.path:
    sys.path.insert(0, str(_CORE_DIR))
from confidentiality import external_target_label, sanitize_external_text

LEVELS = ("P0", "P1", "P2")
# 同一 (target,title 前缀) 在该窗口内只发一次（P0 豁免节流除外，由调用方决定）
DEFAULT_THROTTLE_SECONDS = 1800


@dataclass
class NotifyEvent:
    level: str                 # P0 | P1 | P2
    title: str                 # 一句话结论（结论+级别；勿含敏感值）
    body: str = ""             # 证据指针 + 需要用户做什么（批准/继续/忽略）
    target: str = ""
    evidence_ref: str = ""     # 证据目录指针，不是证据内容
    ts: float = field(default_factory=time.time)


def _sign(timestamp: int, secret: str) -> str:
    string_to_sign = f"{timestamp}\n{secret}"
    digest = hmac.new(string_to_sign.encode("utf-8"), digestmod=hashlib.sha256).digest()
    return base64.b64encode(digest).decode("utf-8")


def build_payload(event: NotifyEvent, secret: str = "") -> dict:
    """构造飞书自定义机器人消息体（含可选签名）。只放脱敏后的结论与指针。"""
    content = f"[{event.level}] {sanitize_external_text(event.title, limit=240)}"
    extras = []
    if event.target:
        extras.append(f"目标: {external_target_label(event.target)}")
    if event.evidence_ref:
        extras.append("证据状态: 仅保存在本机，不通过飞书外发")
    if event.body:
        extras.append(sanitize_external_text(event.body, limit=1000))
    text = content + ("\n" + "\n".join(extras) if extras else "")
    msg: dict = {"msg_type": "text", "content": {"text": text}}
    if secret:
        ts = int(time.time())
        msg["timestamp"] = str(ts)
        msg["sign"] = _sign(ts, secret)
    return msg


class Throttler:
    """文件态节流器：state_path 记录最近发送的 (key -> ts)；P0 默认不节流。"""

    def __init__(self, state_path: Path, window: int = DEFAULT_THROTTLE_SECONDS):
        self.state_path = state_path
        self.window = window

    def allow(self, event: NotifyEvent) -> bool:
        if event.level == "P0":
            return True
        key = f"{event.target}|{event.title[:32]}"
        state = {}
        if self.state_path.is_file():
            try:
                state = json.loads(self.state_path.read_text(encoding="utf-8"))
            except Exception:
                state = {}
        last = float(state.get(key) or 0)
        if time.time() - last < self.window:
            return False
        state[key] = time.time()
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")
        return True


def send(webhook: str, payload: dict, timeout: int = 10) -> tuple[bool, str]:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(webhook, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            ok = '"code":0' in body or '"StatusCode":0' in body
            return ok, body[:300]
    except Exception as exc:  # 通知失败不阻断主流程
        return False, str(exc)


def notify(event: NotifyEvent, *, webhook: str = "", secret: str = "",
           throttler: Throttler | None = None, dry_run: bool = False) -> dict:
    webhook = webhook or os.environ.get("FEISHU_WEBHOOK", "")
    secret = secret or os.environ.get("FEISHU_SECRET", "")
    if event.level not in LEVELS:
        return {"ok": False, "error": f"bad_level:{event.level}"}
    if throttler and not throttler.allow(event):
        return {"ok": True, "suppressed": "throttled"}
    payload = build_payload(event, secret)
    if dry_run:
        return {"ok": True, "dry_run": True, "payload": payload}
    if not webhook:
        return {"ok": False, "error": "FEISHU_WEBHOOK 未配置（设为 env 或参数传入）"}
    ok, detail = send(webhook, payload)
    return {"ok": ok, "detail": detail}


def _self_test() -> int:
    ev = NotifyEvent(level="P0", title="confirmed: ThinkPHP debug 页泄露配置", target="t1",
                     evidence_ref="evidence/t1/FIND-DBG-001", body="需要你：确认是否提交 SRC")
    p = build_payload(ev)
    assert p["msg_type"] == "text" and "confirmed" in p["content"]["text"] and "仅保存在本机" in p["content"]["text"]
    p2 = build_payload(ev, secret="abc")
    assert "timestamp" in p2 and "sign" in p2 and len(p2["sign"]) > 20
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        th = Throttler(Path(tmp) / "state.json", window=60)
        p1_ev = NotifyEvent(level="P1", title="阶段收口", target="t1")
        assert th.allow(p1_ev) is True
        assert th.allow(p1_ev) is False  # 窗口内被节流
        assert th.allow(ev) is True      # P0 不节流
    out = notify(ev, dry_run=True)
    assert out["ok"] and out["dry_run"]
    bad = notify(NotifyEvent(level="P9", title="x"), dry_run=True)
    assert not bad["ok"]
    print("feishu_notifier self-test ok")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="飞书播报（单向只出不进）")
    ap.add_argument("--level", default="P1", choices=LEVELS)
    ap.add_argument("--title", default="")
    ap.add_argument("--body", default="")
    ap.add_argument("--target", default="")
    ap.add_argument("--evidence-ref", default="")
    ap.add_argument("--webhook", default="")
    ap.add_argument("--secret", default="")
    ap.add_argument("--state-file", default="", help="节流状态文件（P1/P2 用）")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return _self_test()
    if not args.title:
        print(json.dumps({"ok": False, "error": "title 必填"}, ensure_ascii=False))
        return 2
    throttler = Throttler(Path(args.state_file)) if args.state_file else None
    result = notify(
        NotifyEvent(level=args.level, title=args.title, body=args.body,
                    target=args.target, evidence_ref=args.evidence_ref),
        webhook=args.webhook, secret=args.secret, throttler=throttler, dry_run=args.dry_run,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
