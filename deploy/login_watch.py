#!/usr/bin/env python3
"""login_watch：VPS 新登录 IP 监控 → 飞书 pa-安全告警群（中断续接项）。

原理：增量解析 SSH auth 日志（/var/log/auth.log 或 /var/log/secure）中
"Accepted password/publickey for <user> from <ip>" 行；IP 不在已知清单 → 告警。
状态文件记录已读偏移 + 已知 IP 集，重启不重复告警。

设计纪律：
- 只读本机日志；不外发任何日志内容，告警只含 user/IP/时间/来源端口。
- 已知 IP 清单持久化（known_ips.json）；首次运行把历史 IP 全量登记为已知（不告警），
  只告警之后出现的新 IP（避免首次跑轰炸）。
- 与 notify 层集成：--notify-cmd 注入（默认调用 feishu_client 的发送函数做 dry-run 打印；
  生产接 notifier.notify_security()）。

用法（VPS cron/systemd timer 每分钟跑）：
  python login_watch.py --log /var/log/auth.log
  python login_watch.py --self-test
"""
from __future__ import annotations

import argparse
import json
import os
import re
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

ACCEPTED_RE = re.compile(
    r"^(?P<ts>\w+\s+\d+\s[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+Accepted\s+\S+\s+for\s+"
    r"(?P<user>\S+)\s+from\s+(?P<ip>[\d.]+)\s+port\s+(?P<port>\d+)")
FAILED_RE = re.compile(r"sshd\[\d+\]:\s+Failed\s+\S+\s+for\s+.*from\s+(?P<ip>[\d.]+)")

DEFAULT_STATE = "login_watch_state.json"


def _load_state(path: Path) -> Dict[str, Any]:
    if path.is_file():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"offset": 0, "known_ips": [], "initialized": False}


def _save_state(path: Path, state: Dict[str, Any]) -> None:
    path.write_text(json.dumps(state, ensure_ascii=False, indent=1), encoding="utf-8")


def scan_log(log_path: Path, state: Dict[str, Any]) -> Dict[str, Any]:
    """增量扫描。返回 {new_logins:[...], failed_burst_ips:[...]}。"""
    if not log_path.is_file():
        return {"new_logins": [], "failed_burst_ips": [], "error": f"log_missing:{log_path}"}
    size = log_path.stat().st_size
    offset = int(state.get("offset") or 0)
    if offset > size:  # 日志轮转过
        offset = 0
    new_logins: List[Dict[str, str]] = []
    failed_counter: Dict[str, int] = {}
    with log_path.open("r", encoding="utf-8", errors="replace") as f:
        f.seek(offset)
        for line in f:
            m = ACCEPTED_RE.search(line)
            if m:
                new_logins.append({"user": m.group("user"), "ip": m.group("ip"),
                                   "port": m.group("port"), "ts": m.group("ts")})
                continue
            fm = FAILED_RE.search(line)
            if fm:
                ip = fm.group("ip")
                failed_counter[ip] = failed_counter.get(ip, 0) + 1
        state["offset"] = f.tell()
    failed_burst = [ip for ip, n in failed_counter.items() if n >= 10]
    return {"new_logins": new_logins, "failed_burst_ips": failed_burst}


def run_once(log_path: Path, state_path: Path,
             notify: Callable[[str], None]) -> Dict[str, Any]:
    state = _load_state(state_path)
    known = set(state.get("known_ips") or [])
    result = scan_log(log_path, state)
    alerts: List[str] = []
    if not state.get("initialized"):
        # 首次运行：历史 IP 全量登记为已知，不告警
        for entry in result["new_logins"]:
            known.add(entry["ip"])
        state["initialized"] = True
        alerts.append(f"login_watch 初始化完成，登记已知 IP {len(known)} 个")
    else:
        for entry in result["new_logins"]:
            if entry["ip"] not in known:
                alerts.append(f"新登录 IP 告警: user={entry['user']} ip={entry['ip']} "
                              f"port={entry['port']} time={entry['ts']}")
                known.add(entry["ip"])
    for ip in result["failed_burst_ips"]:
        alerts.append(f"爆破迹象: {ip} 连续失败登录 ≥10 次（本窗口）")
    state["known_ips"] = sorted(known)
    _save_state(state_path, state)
    for a in alerts:
        notify(a)
    return {"ok": True, "alerts": alerts, "known_ips": len(known)}


def _self_test() -> int:
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        log = Path(tmp) / "auth.log"
        state = Path(tmp) / DEFAULT_STATE
        log.write_text(
            "Aug  8 09:00:01 vps sshd[100]: Accepted publickey for root from 1.2.3.4 port 5555\n"
            "Aug  8 09:01:01 vps sshd[101]: Failed password for root from 9.9.9.9 port 22\n",
            encoding="utf-8")
        sent: List[str] = []
        # 首次运行：初始化不告警
        r1 = run_once(log, state, sent.append)
        assert r1["ok"] and not any("新登录" in a for a in r1["alerts"]), r1
        assert "1.2.3.4" in json.loads(state.read_text(encoding="utf-8"))["known_ips"]
        # 追加新 IP 登录 → 告警
        with log.open("a", encoding="utf-8") as f:
            f.write("Aug  8 09:05:01 vps sshd[102]: Accepted password for deploy from 5.6.7.8 port 6000\n")
        r2 = run_once(log, state, sent.append)
        assert any("5.6.7.8" in a for a in r2["alerts"]), r2
        # 重复跑不重复告警
        r3 = run_once(log, state, sent.append)
        assert not any("5.6.7.8" in a for a in r3["alerts"]), r3
        # 爆破迹象
        with log.open("a", encoding="utf-8") as f:
            for i in range(12):
                f.write(f"Aug  8 09:1{i % 10}:0{i} vps sshd[2{i}]: Failed password for root from 7.7.7.7 port 22\n")
        r4 = run_once(log, state, sent.append)
        assert any("7.7.7.7" in a and "爆破" in a for a in r4["alerts"]), r4
    print("login_watch self-test ok")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="VPS 新登录 IP 监控")
    ap.add_argument("--log", default="/var/log/auth.log")
    ap.add_argument("--state", default=DEFAULT_STATE)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return _self_test()
    log = Path(args.log)
    if not log.is_file() and Path("/var/log/secure").is_file():
        log = Path("/var/log/secure")

    def notify(msg: str) -> None:
        # 生产接 notifier 的 pa-安全告警群路由；默认打印（systemd journal 可见）
        print(json.dumps({"alert": msg, "ts": time.strftime("%F %T")}, ensure_ascii=False))

    out = run_once(log, Path(args.state), notify)
    print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
