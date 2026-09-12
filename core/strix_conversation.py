#!/usr/bin/env python3
"""#F1 读 Strix 真实多智能体对话 —— webui 对话台的"芯"。

Strix 每次跑把完整对话存进 <task>/strix_runs/<run>/.state/agents.db(SQLite):
  agent_sessions(session_id, created_at, updated_at)   # 每个 agent 一行
  agent_messages(id, session_id, message_data, created_at)  # message_data=JSON(OpenAI Responses 格式)
    role=user            → 任务/指令
    role=assistant       → 推理原文(content=[{text,...}])
    type=function_call   → 工具调用(name + arguments[JSON字符串] + call_id)
    type=function_call_output → 工具返回(output[JSON字符串] + call_id,按 call_id 配对上面)
agents.json(同目录 .state/):{statuses, parent_of, names, metadata} = agent 树。

本模块**只读**解析成归一对话事件流(供 control_plane 投影给对话台渲染):
  {seq, ts, agent_id, kind, ...payload}
  kind ∈ user_message | assistant_message | tool_call | tool_result
保留 detail 原文(assistant 全文 / tool arguments 全文 / tool output 全文,各有大上限),
前端折叠看"模型输入 + 工具原始输出"。best-effort:DB 缺/坏/无 sqlite → 返回空,绝不抛。
"""
from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

_FIELD_CAP = int(os.environ.get("CONVO_FIELD_CAP", "16000"))   # 单字段原文上限(防超大 payload)
_MAX_MESSAGES = int(os.environ.get("CONVO_MAX_MESSAGES", "2000"))


def find_run_db(task_dir: str | Path) -> Optional[Path]:
    """在某 task 目录下找最新一次 run 的 agents.db(strix_runs/<run>/.state/agents.db)。"""
    d = Path(task_dir)
    runs = d / "strix_runs"
    if not runs.is_dir():
        # 有的布局 .state 直接在 task 下
        direct = d / ".state" / "agents.db"
        return direct if direct.is_file() else None
    cands: List[Path] = []
    try:
        for run in runs.iterdir():
            db = run / ".state" / "agents.db"
            if db.is_file():
                cands.append(db)
    except OSError:
        return None
    if not cands:
        return None
    # 最新修改的 run
    return max(cands, key=lambda p: p.stat().st_mtime)


def _agents_tree(db_path: Path) -> List[Dict[str, Any]]:
    """读同目录 agents.json → agent 树(id/name/parent/status)。缺失→空。"""
    aj = db_path.parent / "agents.json"
    try:
        j = json.loads(aj.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return []
    if not isinstance(j, dict):
        return []
    names = j.get("names") or {}
    parents = j.get("parent_of") or {}
    statuses = j.get("statuses") or {}
    out: List[Dict[str, Any]] = []
    for aid in names:
        out.append({"agent_id": aid, "name": str(names.get(aid, aid)),
                    "parent": parents.get(aid), "status": str(statuses.get(aid, ""))})
    # Root(parent=None)排前
    out.sort(key=lambda a: (a["parent"] is not None, a["name"]))
    return out


def _cap(s: Any) -> str:
    t = s if isinstance(s, str) else json.dumps(s, ensure_ascii=False)
    return t if len(t) <= _FIELD_CAP else (t[:_FIELD_CAP] + f"\n…(截断,共 {len(t)} 字符)")


def _assistant_text(content: Any) -> str:
    """assistant content 可能是 str 或 [{text,...}] → 合成纯文本原文。"""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for b in content:
            if isinstance(b, dict):
                parts.append(str(b.get("text") or b.get("content") or ""))
            else:
                parts.append(str(b))
        return "\n".join(p for p in parts if p)
    return str(content or "")


def _normalize(md: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """一条 message_data(JSON dict)→ 归一事件 payload(不含 seq/ts/agent_id)。识别不了→None。"""
    role = md.get("role")
    mtype = md.get("type")
    if role == "user":
        return {"kind": "user_message", "text": _cap(md.get("content"))}
    if role == "assistant" or mtype == "message":
        return {"kind": "assistant_message", "text": _cap(_assistant_text(md.get("content"))),
                "status": str(md.get("status", ""))}
    if mtype == "function_call":
        args = md.get("arguments")
        try:
            args_pretty = json.dumps(json.loads(args), ensure_ascii=False, indent=2) if isinstance(args, str) else args
        except (json.JSONDecodeError, TypeError):
            args_pretty = args
        return {"kind": "tool_call", "call_id": str(md.get("call_id", "")),
                "tool_name": str(md.get("name", "")), "tool_args": _cap(args_pretty)}
    if mtype == "function_call_output":
        return {"kind": "tool_result", "call_id": str(md.get("call_id", "")),
                "output": _cap(md.get("output"))}
    if mtype == "reasoning":
        return {"kind": "assistant_message", "text": _cap(md.get("summary") or md.get("content") or ""),
                "reasoning": True}
    return None


def load_conversation(db_path: str | Path, *, limit: int = _MAX_MESSAGES) -> Dict[str, Any]:
    """读 agents.db → {agents:[树], messages:[归一事件], counts}。best-effort,永不抛。"""
    p = Path(db_path)
    if not p.is_file():
        return {"agents": [], "messages": [], "counts": {}}
    agents = _agents_tree(p)
    name_by_id = {a["agent_id"]: a["name"] for a in agents}
    messages: List[Dict[str, Any]] = []
    counts: Dict[str, int] = {}
    try:
        # 只读打开(uri ro),兼容 pa-agent 进程持有的库
        con = sqlite3.connect(f"file:{p}?mode=ro&immutable=1", uri=True, timeout=5)
        cur = con.cursor()
        rows = cur.execute(
            "SELECT id, session_id, message_data, created_at FROM agent_messages ORDER BY id LIMIT ?",
            (limit,)).fetchall()
        con.close()
    except Exception:  # noqa: BLE001 - sqlite 缺/锁/坏 → 空
        return {"agents": agents, "messages": [], "counts": {}}
    for rid, sid, md_raw, created in rows:
        try:
            md = json.loads(md_raw)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(md, dict):
            continue
        ev = _normalize(md)
        if ev is None:
            continue
        ev.update({"seq": rid, "ts": created, "agent_id": sid,
                   "agent_name": name_by_id.get(sid, sid)})
        messages.append(ev)
        counts[ev["kind"]] = counts.get(ev["kind"], 0) + 1
    return {"agents": agents, "messages": messages, "counts": counts}


def load_for_task(task_dir: str | Path, *, limit: int = _MAX_MESSAGES) -> Dict[str, Any]:
    """便捷:给 task 目录 → 找最新 run 的 agents.db → load_conversation。"""
    db = find_run_db(task_dir)
    if db is None:
        return {"agents": [], "messages": [], "counts": {}, "db": None}
    res = load_conversation(db, limit=limit)
    res["db"] = str(db)
    return res


def max_message_id(db_path: str | Path) -> int:
    """给 SSE tail 用:当前 agent_messages 最大 id(0=空/不可读)。"""
    p = Path(db_path)
    if not p.is_file():
        return 0
    try:
        con = sqlite3.connect(f"file:{p}?mode=ro&immutable=1", uri=True, timeout=5)
        m = con.execute("SELECT COALESCE(MAX(id),0) FROM agent_messages").fetchone()[0]
        con.close()
        return int(m or 0)
    except Exception:  # noqa: BLE001
        return 0


def load_since(db_path: str | Path, since_id: int, *, limit: int = 200) -> List[Dict[str, Any]]:
    """给 SSE tail 用:取 id > since_id 的新增事件(增量)。"""
    p = Path(db_path)
    if not p.is_file():
        return []
    agents = _agents_tree(p)
    name_by_id = {a["agent_id"]: a["name"] for a in agents}
    out: List[Dict[str, Any]] = []
    try:
        con = sqlite3.connect(f"file:{p}?mode=ro&immutable=1", uri=True, timeout=5)
        rows = con.execute(
            "SELECT id, session_id, message_data, created_at FROM agent_messages WHERE id > ? ORDER BY id LIMIT ?",
            (int(since_id), limit)).fetchall()
        con.close()
    except Exception:  # noqa: BLE001
        return []
    for rid, sid, md_raw, created in rows:
        try:
            md = json.loads(md_raw)
        except (json.JSONDecodeError, TypeError):
            continue
        ev = _normalize(md) if isinstance(md, dict) else None
        if ev is None:
            continue
        ev.update({"seq": rid, "ts": created, "agent_id": sid, "agent_name": name_by_id.get(sid, sid)})
        out.append(ev)
    return out


def _self_test() -> int:
    import tempfile
    d = Path(tempfile.mkdtemp(prefix="convo_"))
    state = d / "strix_runs" / "run1" / ".state"
    state.mkdir(parents=True)
    # 造 agents.json
    (state / "agents.json").write_text(json.dumps({
        "statuses": {"root1": "completed", "sub1": "completed"},
        "parent_of": {"root1": None, "sub1": "root1"},
        "names": {"root1": "Root Agent", "sub1": "H5 Recon"},
        "metadata": {}}), encoding="utf-8")
    # 造 agents.db(真实 4 类消息)
    db = state / "agents.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE agent_sessions(session_id TEXT, created_at TEXT, updated_at TEXT)")
    con.execute("CREATE TABLE agent_messages(id INTEGER PRIMARY KEY, session_id TEXT, message_data TEXT, created_at TEXT)")
    msgs = [
        ("root1", {"role": "user", "content": "测 https://t.example 的 IDOR"}),
        ("root1", {"role": "assistant", "content": [{"text": "先做侦察,再委派子 agent。"}], "status": "completed"}),
        ("root1", {"type": "function_call", "call_id": "c1", "name": "create_todos",
                   "arguments": "{\"todos\":[{\"title\":\"recon\"}]}"}),
        ("root1", {"type": "function_call_output", "call_id": "c1",
                   "output": "{\"success\":true}"}),
        ("sub1", {"role": "assistant", "content": [{"text": "抓到 /api/order?id=1 可越权。"}]}),
        ("sub1", {"type": "reasoning", "summary": "端点未校验归属"}),
    ]
    for i, (sid, md) in enumerate(msgs, 1):
        con.execute("INSERT INTO agent_messages(id, session_id, message_data, created_at) VALUES(?,?,?,?)",
                    (i, sid, json.dumps(md, ensure_ascii=False), f"2026-08-15T0{i}:00"))
    con.commit(); con.close()

    # find_run_db
    found = find_run_db(d)
    assert found == db, found
    res = load_for_task(d)
    assert res["db"] == str(db)
    # agent 树:Root 在前
    assert [a["name"] for a in res["agents"]] == ["Root Agent", "H5 Recon"], res["agents"]
    msgs_out = res["messages"]
    assert len(msgs_out) == 6, len(msgs_out)
    kinds = [m["kind"] for m in msgs_out]
    assert kinds == ["user_message", "assistant_message", "tool_call", "tool_result",
                     "assistant_message", "assistant_message"], kinds
    # user 文本
    assert "IDOR" in msgs_out[0]["text"]
    # assistant 原文(content[].text 合成)
    assert "委派子 agent" in msgs_out[1]["text"]
    # tool_call:name + args 全文(pretty)
    assert msgs_out[2]["tool_name"] == "create_todos" and "recon" in msgs_out[2]["tool_args"]
    # tool_result 按 call_id 配对(前端用)
    assert msgs_out[3]["call_id"] == msgs_out[2]["call_id"] == "c1"
    assert "success" in msgs_out[3]["output"]
    # 子 agent 归属
    assert msgs_out[4]["agent_id"] == "sub1" and msgs_out[4]["agent_name"] == "H5 Recon"
    # reasoning 归到 assistant_message + reasoning 标记
    assert msgs_out[5].get("reasoning") is True and "未校验归属" in msgs_out[5]["text"]
    # counts
    assert res["counts"]["assistant_message"] == 3 and res["counts"]["tool_call"] == 1

    # SSE tail:max id + 增量
    assert max_message_id(db) == 6
    since = load_since(db, 4)
    assert [m["seq"] for m in since] == [5, 6], since

    # detail 截断:超大字段
    big = "A" * (_FIELD_CAP + 500)
    con2 = sqlite3.connect(db)
    con2.execute("INSERT INTO agent_messages(id,session_id,message_data,created_at) VALUES(7,'root1',?,?)",
                 (json.dumps({"role": "user", "content": big}), "2026-08-15T07:00"))
    con2.commit(); con2.close()
    r2 = load_conversation(db)
    last = r2["messages"][-1]
    assert last["text"].endswith("字符)") and len(last["text"]) < _FIELD_CAP + 60, len(last["text"])

    # 缺库 → 空,不抛
    assert load_conversation(d / "nope.db")["messages"] == []
    assert load_for_task(Path(tempfile.mkdtemp()))["db"] is None

    print("strix_conversation self-test ok (find_db/agent树/4类归一/call_id配对/子agent归属/reasoning/counts/SSE增量/截断/缺库容错)")
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())
