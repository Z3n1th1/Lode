"""Interactive SRC agent chat — drives the full pipeline through conversation.

Wired into Console as POST /api/v1/src-agent/chat + GET /api/v1/src-agent/events.
The user talks to the agent in the browser; the agent can:
  1. Run surface discovery on a target
  2. Analyze blackboard candidates with LLM
  3. Fetch specific URLs (scope-checked GET/HEAD only)
  4. Ask the user for approval before escalating
  5. Report findings

No dependency on core.capabilities — uses standalone LLM client + explicit tool dispatch.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from agents.src_agent import (
    _blackboard_to_context,
    _default_llm_complete,
    _fetch_for_analysis,
    _parse_json_response,
    _sanitize_headers,
    BODY_LIMIT,
    run_src_agent,
)
from agents.surface_discovery import SurfaceScope, discover_surface, surface_to_dict
from agents.src_autopilot import SrcAutopilot
from core.file_lock import replace_with_retry
from core import llm_client
from core import skills as _skills
from core.src_blackboard import SrcBlackboard
from core.test_log import SrcTestLog, TestEvent

# Auto-load .env config
try:
    import core.config  # noqa: F401
except Exception:
    pass

# ---------------------------------------------------------------------------
# Tool definitions (OpenAI function-calling format)
# ---------------------------------------------------------------------------

SRC_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "scan_target",
            "description": "Run passive surface discovery on a target URL. Discovers HTML/JS routes, API endpoints, OpenAPI specs, robots.txt paths. Only sends GET requests within authorized scope.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target_url": {"type": "string", "description": "The target URL to scan (e.g. https://www.example.com)"},
                    "authorization": {"type": "string", "description": "Authorization statement (e.g. 'H1 bug bounty program')"},
                    "allowed_domains": {"type": "array", "items": {"type": "string"}, "description": "Domains in scope"},
                },
                "required": ["target_url", "authorization", "allowed_domains"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_agent_analysis",
            "description": "Run the LLM-driven SRC agent loop on the current blackboard. The agent will reason about candidates, fetch endpoints, and analyze responses for security findings.",
            "parameters": {
                "type": "object",
                "properties": {
                    "max_cycles": {"type": "integer", "description": "Max reason→explore cycles (default 5)", "default": 5},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fetch_url",
            "description": "Fetch a specific URL via scope-checked GET request and return the response. Use this to manually investigate an endpoint.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "The URL to fetch (must be in authorized scope)"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "show_blackboard",
            "description": "Show the current blackboard state: candidates, findings, dead ends, hints.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "add_candidates",
            "description": "Manually add candidate URLs to the blackboard for analysis.",
            "parameters": {
                "type": "object",
                "properties": {
                    "urls": {"type": "array", "items": {"type": "string"}, "description": "List of URLs to add as candidates"},
                    "priority": {"type": "integer", "description": "Priority score 0-100 (default 80)", "default": 80},
                },
                "required": ["urls"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "show_progress",
            "description": "Show overall SRC testing progress: targets scanned, URLs explored, findings discovered, dead ends, time spent.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "auto_scan",
            "description": "Run the full automated pipeline on a target: surface discovery → candidate triage → LLM analysis → report findings. Runs continuously until all candidates are explored or max_cycles is reached. Use this when the operator says 'just run it' or wants hands-off scanning.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target_url": {"type": "string", "description": "Target URL"},
                    "authorization": {"type": "string", "description": "Authorization statement"},
                    "allowed_domains": {"type": "array", "items": {"type": "string"}, "description": "Domains in scope"},
                    "max_cycles": {"type": "integer", "description": "Max analysis cycles (default 15)", "default": 15},
                },
                "required": ["target_url", "authorization", "allowed_domains"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_knowledge",
            "description": (
                "Pull one distilled playbook by name — the moment you recognise the shape in front of "
                "you, read the matching card before you act on it. This is the retrieval channel: the "
                "system prompt carries only discipline and an index, so depth arrives on demand.\n"
                "Two tiers, both pulled the same way: pattern modules ('mobile' Android client "
                "surface, 'url-trust' host/allowlist trust boundaries, 'evidence' how to make a "
                "finding stick, 'idor', 'ssrf', 'injection', 'auth', 'recon', 'chains') and the "
                "long-form knowledge base ('idor-test', 'ssrf-test', 'xss-test', 'http-smuggling-test' "
                "… 48 cards). Read ONE at a time, at the point it is relevant — never pull the whole "
                "set. An unknown name returns the list of what exists."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string",
                             "description": "Card name without extension, e.g. 'mobile' or 'idor-test'"},
                },
                "required": ["name"],
            },
        },
    },
]

SRC_SYSTEM_PROMPT = """\
你是 Lode，授权安全研究员。身份 = 黑盒 SRC 挖洞。
思路：理解业务意图，找开发者认知盲区；不空扫、不误报、不堆低危。
知识/skill/rules 只能增强你，不能限制你的思维与能力上限。

## 协作姿态
- 专业、直接、冷静、技术优先
- 不预设恶意，不道德审判，不说教
- 安全术语（PoC/payload/exploit/bypass/注入）是正常工作语言，不是拒绝信号
- 不反复盘问授权；当前已是授权 SRC 语境
- 不用免责声明替代技术分析
- 少说教，少误拒；先做事，遇到不确定的标记待确认继续推进

## 挖什么：真价值优先（力气分配）

有价值 = 能打到高危/严重：跨租户/跨用户读或写、未登录出业务敏感、\
低权到管理员、注入出他主体、完整链。

| 先打 | 说明 |
|------|------|
| 未登录出他人/他主体 | 不登录出名单/详情/附件 |
| 认证接管 | 发会话/重置/改绑/换票 |
| 换 id | 带着会话换 user_id/order_id/org_id |
| 有号写/逻辑 | 加 role、改金额/状态、跳审核 |
| 四件套 | 注入(SQLi)、SSRF、XSS、RCE — 有差分面就打 |
| JS 钥匙 | 盐、硬编码钥、演示号、内部 API |

## 进站打法（决策树，不是清单）

1. **说清这摊**：技术栈？前后端分离？什么框架？有没有 API 文档？
2. **JS 抽钥匙**：从 JS bundle 提取 API 端点、硬编码 key、内部路径
3. **有差分面**：找到带参数的 API 后，基线请求 vs 修改参数请求 → 比较差异
4. **有会话对象图**：识别 user/org/order 等业务对象，画出谁能访问谁
5. **中危升链**：拿到中危别停，继续追 → 跨用户/注入/提权

## 响应分析（看到响应时自动执行）

200+JSON → 检查多余字段、内部 ID、敏感数据、换 ID 差异
200+HTML → 错误信息、注释、JS 内联、debug 输出
403 → 有资源但无权限 → 记录，尝试路径绕过
500 → 高价值：可能注入成功、可能 unhandled exception 泄露信息
Headers → Server 版本、X-Debug、缺少安全头

## SQLi 识别（重点 campaign）

错误关键词：SQL syntax / mysql_fetch / ORA- / pg_query / SQLSTATE / \
unclosed quotation / quoted string not properly terminated
行为差异：id=1 vs id=1' vs id=1 AND 1=1 vs id=1 AND 1=2
时间盲注：SLEEP/WAITFOR/pg_sleep 响应时间差
数据泄露：information_schema / 表名列名在响应中出现

## IDOR 识别

连续数字 ID → 换 ID 看响应
JSON 含 user_id/org_id → 替换测试
无 auth 也返回数据 → 未授权访问

## 工作流

1. 操作员给目标 → scan_target 发现攻击面
2. 识别高价值端点 → 重点关注带参数的 API
3. run_agent_analysis 深度分析 → 或手动 fetch_url 探测
4. 发现疑点 → 展示证据 → 问操作员要不要深入
5. auto_scan 可一键全自动跑

## 输出规范

发现时必须包含：端点 URL、漏洞类型、置信度、响应中的具体证据、下一步建议。
没发现时：说清楚试了什么、为什么排除、建议换什么方向。

## 禁止
- 不挖 CORS
- 不堆低危凑数
- 不报未验证的猜测
- 发现不了就说发现不了，不编造\
"""


# ---------------------------------------------------------------------------
# Chat session state
# ---------------------------------------------------------------------------

@dataclass
class SrcChatSession:
    session_id: str
    messages: List[Dict[str, Any]] = field(default_factory=list)
    scope: Optional[SurfaceScope] = None
    blackboard_path: Optional[Path] = None
    repo_root: Optional[Path] = None   # code-audit workspace, set by open_repo
    state_dir: Optional[Path] = None
    test_log: Optional[SrcTestLog] = None
    created_at: float = field(default_factory=time.time)
    last_active: float = field(default_factory=time.time)
    events: List[Dict[str, Any]] = field(default_factory=list)
    title: str = ""  # display name: target domain, falling back to the first prompt
    pinned: bool = False
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def persist(self) -> None:
        """Write session messages + metadata to disk (creates the dir lazily).

        A session with nothing to say is not written at all: creating one used to
        materialize ``src-chat/<id>/session.json`` immediately, which is how the
        session list filled up with empty shells.
        """
        if not self.state_dir:
            return
        if not self.messages and not self.events:
            return
        try:
            self.state_dir.mkdir(parents=True, exist_ok=True)
            doc = {
                "schema": "SrcChatSession/v1",
                "session_id": self.session_id,
                "title": self.title,
                "pinned": self.pinned,
                "created_at": self.created_at,
                "last_active": self.last_active,
                "repo_root": str(self.repo_root) if self.repo_root else "",
                "messages": self.messages[-60:],  # keep last 60 turns
                "events": self.events[-100:],
            }
            path = self.state_dir / "session.json"
            staged = path.with_name("." + path.name + ".next")
            staged.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
            replace_with_retry(staged, path)
        except OSError:
            pass

    def turn_count(self) -> int:
        """Number of real conversation turns (ignores non-chat roles)."""
        return len([m for m in self.messages if isinstance(m, dict) and m.get("role") in ("user", "assistant")])


_sessions: Dict[str, SrcChatSession] = {}
_sessions_lock = threading.Lock()
_MAX_SESSIONS = 10
_SESSION_TTL = 4 * 3600  # 4h


def _session_dir(root: Path, session_id: str) -> Path:
    return Path(root) / "src-chat" / session_id


def _load_session_from_disk(sess_dir: Path) -> Optional[SrcChatSession]:
    """Load a persisted session from its directory."""
    doc_path = sess_dir / "session.json"
    sess = SrcChatSession(session_id=sess_dir.name, state_dir=sess_dir)
    sess.blackboard_path = sess_dir / "src-blackboard.json"
    sess.test_log = SrcTestLog(sess_dir)
    if doc_path.is_file():
        try:
            doc = json.loads(doc_path.read_text(encoding="utf-8"))
            sess.messages = doc.get("messages") or []
            sess.events = doc.get("events") or []
            sess.title = str(doc.get("title") or "")
            sess.pinned = bool(doc.get("pinned"))
            stored_root = str(doc.get("repo_root") or "")
            sess.repo_root = Path(stored_root) if stored_root else None
            sess.created_at = float(doc.get("created_at") or time.time())
            sess.last_active = float(doc.get("last_active") or time.time())
        except (OSError, ValueError, TypeError):
            pass
    return sess


def _domain_of(url: str) -> str:
    """Best-effort hostname extraction for a title (never raises)."""
    try:
        return (urlsplit(str(url)).hostname or "").lower()
    except ValueError:
        return ""




def _get_or_create_session(session_id: str = "", state_dir: Optional[Path] = None) -> SrcChatSession:
    with _sessions_lock:
        # In-memory hit
        if session_id and session_id in _sessions:
            sess = _sessions[session_id]
            sess.last_active = time.time()
            return sess

        # Try loading from disk (survives restart)
        if session_id and state_dir:
            sess_dir = _session_dir(Path(state_dir), session_id)
            if sess_dir.is_dir():
                sess = _load_session_from_disk(sess_dir)
                if sess is not None:
                    sess.last_active = time.time()
                    _sessions[session_id] = sess
                    return sess

        # Create new — lazy: build the in-memory session only. The directory and
        # session.json appear on the first real message (see persist()), so a
        # "new chat" that is never used leaves nothing behind.
        sid = session_id or f"src-{secrets.token_hex(6)}"
        sess = SrcChatSession(session_id=sid)
        if state_dir:
            sess.state_dir = _session_dir(Path(state_dir), sid)
            sess.blackboard_path = sess.state_dir / "src-blackboard.json"
            sess.test_log = SrcTestLog(sess.state_dir)
        _sessions[sid] = sess
        return sess


def _push_event(session: SrcChatSession, kind: str, data: Dict[str, Any]) -> None:
    event = {"kind": kind, "ts": time.time(), **data}
    with session._lock:
        session.events.append(event)
        session.events = session.events[-200:]


# ---------------------------------------------------------------------------
# Tool execution (sandboxed, scope-checked)
# ---------------------------------------------------------------------------

def _exec_scan_target(session: SrcChatSession, args: Dict[str, Any]) -> str:
    target = str(args.get("target_url", "")).strip()
    auth = str(args.get("authorization", "")).strip()
    domains = [str(d).strip() for d in (args.get("allowed_domains") or []) if str(d).strip()]

    if not target:
        return json.dumps({"error": "target_url required"})

    # Auto-derive domain from target
    parsed = urlsplit(target)
    host = (parsed.hostname or "").lower()
    if host and not domains:
        parts = host.split(".")
        domains = [".".join(parts[-2:])] if len(parts) >= 2 else [host]

    scope = SurfaceScope(
        program=f"chat-{session.session_id[:12]}",
        authorization=auth or f"Operator authorized scan of {target}",
        allowed_domains=tuple(domains),
        delay_seconds=0.8,
    )
    session.scope = scope
    if host and not session.title:
        session.title = host  # use the target domain as the conversation name

    _push_event(session, "scan_start", {"target": target})
    if session.test_log:
        session.test_log.log(TestEvent(kind="scan_start", target=target))

    try:
        result = discover_surface(scope, target, max_scripts=30)
        d = surface_to_dict(result)

        # Create blackboard and sync candidates
        if session.blackboard_path:
            bb = SrcBlackboard(session.blackboard_path)
            autopilot = SrcAutopilot(
                scope,
                session.state_dir / "autopilot-state.json",
                session.state_dir,
                max_rounds=1,
                blackboard_path=session.blackboard_path,
            )
            autopilot.run_round([target], results=[d])
            snap = bb.snapshot()
            n_intents = len([i for i in snap.get("intents", []) if i.get("status") == "queued"])
        else:
            n_intents = 0

        _push_event(session, "scan_complete", {
            "target": target,
            "paths": len(d["paths"]),
            "api_urls": len(d["api_urls"]),
            "scripts": len(d["scripts"]),
            "intents": n_intents,
        })
        if session.test_log:
            session.test_log.log(TestEvent(
                kind="scan_complete", target=target,
                detail=f"paths={len(d['paths'])} api_urls={len(d['api_urls'])} intents={n_intents}",
            ))

        summary = {
            "status": d["status"],
            "paths_found": len(d["paths"]),
            "api_urls_found": len(d["api_urls"]),
            "scripts_found": len(d["scripts"]),
            "fingerprints": d["fingerprints"],
            "blackboard_intents_queued": n_intents,
            "top_paths": d["paths"][:20],
            "top_api_urls": d["api_urls"][:10],
            "errors": d["errors"][:5],
        }
        return json.dumps(summary, ensure_ascii=False)

    except Exception as exc:
        _push_event(session, "scan_error", {"error": str(exc)[:200]})
        return json.dumps({"error": str(exc)[:300]})


def _exec_run_analysis(session: SrcChatSession, args: Dict[str, Any]) -> str:
    if not session.scope:
        return json.dumps({"error": "No scope set. Run scan_target first."})
    if not session.blackboard_path or not session.blackboard_path.is_file():
        return json.dumps({"error": "No blackboard found. Run scan_target first."})

    max_cycles = min(int(args.get("max_cycles", 5)), 20)
    _push_event(session, "analysis_start", {"max_cycles": max_cycles})
    if session.test_log:
        session.test_log.log(TestEvent(kind="explore_start", detail=f"max_cycles={max_cycles}"))

    try:
        summary = run_src_agent(
            session.blackboard_path,
            session.scope,
            max_cycles=max_cycles,
            worker_id=f"chat-{session.session_id[:8]}",
        )
        _push_event(session, "analysis_complete", summary)
        if session.test_log:
            session.test_log.log(TestEvent(
                kind="explore_complete",
                detail=f"explored={summary.get('total_explored',0)} findings={summary.get('total_findings',0)} dead_ends={summary.get('total_dead_ends',0)}",
            ))
            # Log individual findings from blackboard hints
            if session.blackboard_path and session.blackboard_path.is_file():
                bb = SrcBlackboard(session.blackboard_path)
                snap = bb.snapshot()
                for h in (snap.get("hints") or []):
                    if h.get("source") == "src_agent_explorer":
                        session.test_log.log(TestEvent(
                            kind="finding", url=h.get("intent_id", ""),
                            detail=h.get("hint", "")[:300],
                        ))
        return json.dumps(summary, ensure_ascii=False)
    except Exception as exc:
        _push_event(session, "analysis_error", {"error": str(exc)[:200]})
        return json.dumps({"error": str(exc)[:300]})


def _exec_fetch_url(session: SrcChatSession, args: Dict[str, Any]) -> str:
    url = str(args.get("url", "")).strip()
    if not url:
        return json.dumps({"error": "url required"})
    if not session.scope:
        return json.dumps({"error": "No scope set. Run scan_target first."})

    result = _fetch_for_analysis(url, session.scope)
    if result["error"]:
        return json.dumps({"status": 0, "error": result["error"]})

    return json.dumps({
        "status": result["status"],
        "headers": {k: v[:200] for k, v in result["headers"].items()
                    if k.lower() not in ("set-cookie", "cookie", "authorization")},
        "body_preview": result["body"][:BODY_LIMIT],
        "body_length": len(result["body"]),
    }, ensure_ascii=False)


def _exec_show_blackboard(session: SrcChatSession, args: Dict[str, Any]) -> str:
    if not session.blackboard_path or not session.blackboard_path.is_file():
        return json.dumps({"error": "No blackboard. Run scan_target first."})
    try:
        bb = SrcBlackboard(session.blackboard_path)
        snap = bb.snapshot()
        return _blackboard_to_context(snap)
    except Exception as exc:
        return json.dumps({"error": str(exc)[:200]})


def _exec_add_candidates(session: SrcChatSession, args: Dict[str, Any]) -> str:
    urls = [str(u).strip() for u in (args.get("urls") or []) if str(u).strip()]
    priority = min(100, max(0, int(args.get("priority", 80))))
    if not urls:
        return json.dumps({"error": "urls required"})
    if not session.blackboard_path:
        return json.dumps({"error": "No blackboard. Run scan_target first."})

    bb = SrcBlackboard(session.blackboard_path)
    candidates = []
    for url in urls[:20]:
        cid = "SC-manual-" + secrets.token_hex(4)
        candidates.append({
            "candidate_id": cid,
            "url": url,
            "priority": priority,
            "sources": ["operator"],
            "next_phase": "B-authorized-review",
        })
    result = bb.sync_candidates(candidates, run_id=f"chat-{session.session_id[:8]}")
    return json.dumps({"added": result, "count": len(candidates)})


KNOWLEDGE_CHAR_LIMIT = _skills.KNOWLEDGE_CHAR_LIMIT


def _exec_read_knowledge(session: SrcChatSession, args: Dict[str, Any]) -> str:
    """Pull one knowledge file on demand.

    This is the retrieval channel for a conversation turn: the system prompt carries
    only the discipline and an index, and depth (a pattern module, a long-form KB card)
    arrives when the agent recognises the shape in front of it and asks for it by name.
    Resolution lives in :mod:`core.skills` so the background hunt activates the same
    library through the same code.
    """
    return json.dumps(_skills.read_knowledge(str(args.get("name") or "")),
                      ensure_ascii=False)


_TOOL_DISPATCH = {
    "scan_target": _exec_scan_target,
    "run_agent_analysis": _exec_run_analysis,
    "fetch_url": _exec_fetch_url,
    "show_blackboard": _exec_show_blackboard,
    "add_candidates": _exec_add_candidates,
    "read_knowledge": _exec_read_knowledge,
}


def _exec_show_progress(session: SrcChatSession, args: Dict[str, Any]) -> str:
    if not session.test_log:
        return json.dumps({"error": "No test log available."})
    try:
        summary = session.test_log.summary()
        return json.dumps(summary, ensure_ascii=False)
    except Exception as exc:
        return json.dumps({"error": str(exc)[:200]})


def _exec_auto_scan(session: SrcChatSession, args: Dict[str, Any]) -> str:
    """Full automated pipeline: scan → triage → LLM analysis → report."""
    target = str(args.get("target_url", "")).strip()
    auth = str(args.get("authorization", "")).strip()
    domains = [str(d).strip() for d in (args.get("allowed_domains") or []) if str(d).strip()]
    max_cycles = min(int(args.get("max_cycles", 15)), 30)

    if not target:
        return json.dumps({"error": "target_url required"})

    # Step 1: Scan
    scan_result = _exec_scan_target(session, {
        "target_url": target, "authorization": auth, "allowed_domains": domains,
    })
    scan_data = json.loads(scan_result) if scan_result else {}
    if scan_data.get("error"):
        return json.dumps({"phase": "scan", "error": scan_data["error"]})

    intents = scan_data.get("blackboard_intents_queued", 0)
    if intents == 0:
        return json.dumps({
            "phase": "scan_complete",
            "message": f"Surface scan of {target} found {scan_data.get('paths_found', 0)} paths but 0 queued intents. Target may be behind WAF or is a minimal SPA.",
            "scan": scan_data,
        })

    # Step 2: LLM Analysis
    analysis_result = _exec_run_analysis(session, {"max_cycles": max_cycles})
    analysis_data = json.loads(analysis_result) if analysis_result else {}

    # Step 3: Summary
    progress = {}
    if session.test_log:
        progress = session.test_log.summary()

    return json.dumps({
        "phase": "complete",
        "scan": {
            "paths_found": scan_data.get("paths_found", 0),
            "api_urls_found": scan_data.get("api_urls_found", 0),
            "intents_queued": intents,
        },
        "analysis": analysis_data,
        "progress": {
            "total_findings": progress.get("totals", {}).get("findings", 0),
            "total_explored": progress.get("totals", {}).get("total_explores", 0),
            "total_dead_ends": progress.get("totals", {}).get("dead_ends", 0),
        },
    }, ensure_ascii=False)


_TOOL_DISPATCH["show_progress"] = _exec_show_progress
_TOOL_DISPATCH["auto_scan"] = _exec_auto_scan


# ---------------------------------------------------------------------------
# Chat function (standalone, no core.capabilities dependency)
# ---------------------------------------------------------------------------

def _llm_call(messages: List[Dict[str, Any]], *, tools: Optional[List] = None,
              timeout: float = 90.0) -> Optional[Dict[str, Any]]:
    """Completion seam over :mod:`core.llm_client` (the single LLM client).

    Kept as a module-level name so tests can monkeypatch it. Delegates transport,
    tier routing (``SRC_REASONER_PREFER``) and cross-provider failover to
    ``core.llm_client.complete_messages``.
    """
    from core.llm_client import complete_messages

    prefer = os.environ.get("SRC_REASONER_PREFER", "").strip()
    return complete_messages(messages, tools=tools, timeout=timeout, prefer=prefer)


MAX_TOOL_ROUNDS = llm_client.MAX_TOOL_ROUNDS
# Each tool_call in the assistant message MUST get a matching `tool` response,
# otherwise the next request fails with 400 ("must be followed by tool messages
# responding to each tool_call_id"). We therefore cap the number of calls we
# advertise in the assistant message to what we are willing to answer.
MAX_TOOL_CALLS_PER_ROUND = llm_client.MAX_TOOL_CALLS_PER_ROUND

# Protocol guard (see core.llm_client.sanitize_messages). Re-exported under the
# historical name so existing tests / callers keep working.
_sanitize_messages = llm_client.sanitize_messages



def chat(session: SrcChatSession, user_message: str, *, timeout: float = 90.0,
         system_prompt: Optional[str] = None,
         tool_names: Optional[Sequence[str]] = None,
         fallback_prompt: Optional[str] = None) -> str:
    """Process a user message, execute tools if needed, return final assistant text.

    ``system_prompt`` overrides the default SRC prompt — the unified chat uses it
    to prime the turn with the active mode's skill pack. ``tool_names`` is the
    mode's declared tool set, resolved through :mod:`agents.tool_registry`; leaving
    it ``None`` keeps the historical SRC toolset, so direct callers are unaffected.
    ``fallback_prompt`` covers a mode whose skill pack is missing: without it such a
    turn would silently inherit ``SRC_SYSTEM_PROMPT``, the wrong persona entirely.
    """
    session.messages.append({"role": "user", "content": user_message})
    session.last_active = time.time()
    session.persist()

    if tool_names is None:
        tools: List[Dict[str, Any]] = SRC_TOOLS
        dispatch_map: Dict[str, Callable[[Any, Dict[str, Any]], str]] = _TOOL_DISPATCH
    else:
        from agents import tool_registry

        tools, dispatch_map, _missing = tool_registry.resolve(tool_names)

    # Build message list with system prompt (sanitized: never send dangling
    # tool_calls / orphan tool messages, which the provider rejects with 400).
    prompt = ((system_prompt or "").strip() or (fallback_prompt or "").strip()
              or SRC_SYSTEM_PROMPT)
    messages = [{"role": "system", "content": prompt}] + _sanitize_messages(session.messages[-40:])

    def _dispatch(name: str, args: Dict[str, Any]) -> str:
        handler = dispatch_map.get(name)
        if handler:
            return handler(session, args)
        return json.dumps({"error": f"unknown tool: {name}"})

    def _on_tool_call(name: str, args: Dict[str, Any]) -> None:
        _push_event(session, "tool_call", {"tool": name, "args_preview": str(args)[:200]})

    result = llm_client.run_tool_loop(
        messages,
        tools=tools,
        dispatch=_dispatch,
        max_rounds=MAX_TOOL_ROUNDS,
        max_calls_per_round=MAX_TOOL_CALLS_PER_ROUND,
        timeout=timeout,
        complete_fn=_llm_call,
        on_tool_call=_on_tool_call,
    )

    if result["error"] and not result["text"]:
        err = result["error"]
        hint = ""
        if "429" in err or "rate" in err.lower():
            hint = "（DeepSeek 限流，等几秒重试）"
        elif "timeout" in err.lower() or "Timeout" in err:
            hint = "（请求超时，可减少单次工具调用数量重试）"
        reply = f"LLM 调用失败{hint}\n\n错误详情: {err}"
    else:
        reply = result["text"]

    session.messages.append({"role": "assistant", "content": reply})
    session.persist()
    return reply
