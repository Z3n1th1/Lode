#!/usr/bin/env python3
"""SurfaceForge unified CLI — cross-platform entry point.

Works identically on Windows / Linux / macOS. Auto-loads .env for API keys.

Usage:
  python surfaceforge.py webui                 # start the WebUI
  python surfaceforge.py scan <url>            # surface discovery only
  python surfaceforge.py agent <blackboard>    # LLM agent loop on existing blackboard
  python surfaceforge.py auto <url>            # full: scan → agent → report
  python surfaceforge.py progress              # show test progress summary
  python surfaceforge.py doctor                # environment check
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "core"))

# Auto-load .env
try:
    from core.config import load_dotenv
    load_dotenv()
except Exception:
    pass


def _python() -> str:
    return sys.executable


def cmd_webui(args: argparse.Namespace) -> int:
    """Start the WebUI server."""
    port = str(args.port or os.environ.get("WEBUI_PORT", "8088"))
    state_dir = args.state_dir or os.environ.get("WEBUI_STATE_DIR", str(ROOT / "webui-state"))
    cmd = [
        _python(), "-m", "webui.server",
        "--state-dir", state_dir,
        "--static-dir", str(ROOT / "webui" / "dist"),
        "--port", port,
    ]
    return subprocess.call(cmd, cwd=str(ROOT))


def cmd_scan(args: argparse.Namespace) -> int:
    """Surface discovery + candidate triage."""
    from agents.surface_discovery import SurfaceScope, discover_surface, surface_to_dict, write_surface_outputs
    scope = _load_scope(args.scope)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    result = discover_surface(scope, args.url, max_scripts=args.max_scripts)
    d = surface_to_dict(result)
    json_path, md_path = write_surface_outputs(result, out_dir)
    print(json.dumps({
        "schema": "SurfaceScanSummary/v1",
        "target": args.url,
        "status": d["status"],
        "paths": len(d["paths"]),
        "api_urls": len(d["api_urls"]),
        "scripts": len(d["scripts"]),
        "fingerprints": d["fingerprints"],
        "output_json": str(json_path),
        "output_md": str(md_path),
    }, ensure_ascii=False, indent=2))
    return 0


def cmd_agent(args: argparse.Namespace) -> int:
    """Run the LLM agent loop on an existing blackboard."""
    from agents.src_agent import run_src_agent
    scope = _load_scope(args.scope)
    summary = run_src_agent(
        args.blackboard, scope,
        max_cycles=args.max_cycles,
        reasoner_prefer=args.reasoner_prefer,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


def cmd_auto(args: argparse.Namespace) -> int:
    """Full pipeline: scan → autopilot → LLM agent."""
    from agents.surface_discovery import SurfaceScope
    from agents.src_autopilot import SrcAutopilot
    from agents.src_agent import run_src_agent

    scope = _load_scope(args.scope)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    autopilot = SrcAutopilot(
        scope, out_dir / "autopilot-state.json", out_dir,
        max_rounds=3, max_candidates=200,
    )
    print(f"[1/2] Surface discovery + triage on {args.url} ...", file=sys.stderr)
    autopilot.run_round([args.url])

    bb_path = out_dir / "src-blackboard.json"
    print(f"[2/2] LLM agent analysis (max {args.max_cycles} cycles) ...", file=sys.stderr)
    summary = run_src_agent(
        bb_path, scope,
        max_cycles=args.max_cycles,
        reasoner_prefer=args.reasoner_prefer,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


def cmd_progress(args: argparse.Namespace) -> int:
    """Show test progress summary."""
    from core.test_log import SrcTestLog
    state_dir = Path(args.state_dir or ROOT / "webui-state")
    log = SrcTestLog(state_dir)
    print(json.dumps(log.summary(), ensure_ascii=False, indent=2))
    return 0


def cmd_sessions(args: argparse.Namespace) -> int:
    """List past SRC chat sessions and their state (for resuming)."""
    from core.src_blackboard import SrcBlackboard
    state_dir = Path(args.state_dir or ROOT / "webui-state")
    chat_dir = state_dir / "src-chat"
    if not chat_dir.is_dir():
        print(json.dumps({"sessions": []}, indent=2))
        return 0
    sessions = []
    for sess_dir in sorted(chat_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        if not sess_dir.is_dir():
            continue
        bb_path = sess_dir / "src-blackboard.json"
        info = {
            "session_id": sess_dir.name,
            "updated_at": sess_dir.stat().st_mtime,
            "blackboard_exists": bb_path.is_file(),
        }
        if bb_path.is_file():
            try:
                bb = SrcBlackboard(bb_path)
                snap = bb.snapshot()
                info["facts"] = len(snap.get("facts", []))
                info["intents_queued"] = len([i for i in snap.get("intents", []) if i.get("status") == "queued"])
                info["intents_done"] = len([i for i in snap.get("intents", []) if i.get("status") in ("completed", "dead_end", "blocked")])
                info["hints"] = len(snap.get("hints", []))
            except Exception:
                pass
        sessions.append(info)
    print(json.dumps({"sessions": sessions[:20]}, ensure_ascii=False, indent=2))
    return 0


def cmd_resume(args: argparse.Namespace) -> int:
    """Resume an SRC chat session — continues the agent loop where it left off.

    Reads the session's blackboard (claims expire automatically on restart),
    requeues stale claims, and runs the agent loop until convergence.
    """
    from agents.src_agent import run_src_agent
    from agents.surface_discovery import SurfaceScope
    from core.src_blackboard import SrcBlackboard

    state_dir = Path(args.state_dir or ROOT / "webui-state")
    sess_dir = state_dir / "src-chat" / args.session_id
    if not sess_dir.is_dir():
        print(f"ERROR: session not found: {args.session_id}", file=sys.stderr)
        return 2
    bb_path = sess_dir / "src-blackboard.json"
    if not bb_path.is_file():
        print(f"ERROR: no blackboard in session {args.session_id}", file=sys.stderr)
        return 2

    # Requeue stale claims (process may have died mid-lease)
    bb = SrcBlackboard(bb_path)
    snap = bb.snapshot()
    stale = 0
    for intent in snap.get("intents", []):
        if intent.get("status") == "claimed":
            stale += 1
    print(f"Session {args.session_id}: {stale} stale claims will be reclaimed by lease expiry", file=sys.stderr)

    scope = _load_scope(args.scope)
    summary = run_src_agent(
        bb_path, scope,
        max_cycles=args.max_cycles,
        reasoner_prefer=args.reasoner_prefer,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    """Environment check."""
    import platform
    checks = {
        "python": sys.version.split()[0],
        "platform": platform.system(),
        "arch": platform.machine(),
        "llm_api_key_set": bool(os.environ.get("LLM_API_KEY", "").strip()),
        "llm_base_url": os.environ.get("LLM_BASE_URL", "https://api.deepseek.com"),
        "llm_model": os.environ.get("LLM_MODEL", "deepseek-chat"),
        "env_file": (ROOT / ".env").is_file(),
        "webui_dist": (ROOT / "webui" / "dist" / "index.html").is_file(),
    }
    # Check key modules
    mod_status = {}
    for mod in ("agents.src_agent", "agents.src_chat", "agents.surface_discovery",
                "agents.src_autopilot", "core.src_blackboard", "core.test_log"):
        try:
            __import__(mod)
            mod_status[mod] = "ok"
        except Exception as exc:
            mod_status[mod] = f"FAIL: {type(exc).__name__}"
    checks["modules"] = mod_status
    print(json.dumps(checks, ensure_ascii=False, indent=2))
    ok = checks["llm_api_key_set"] and all(v == "ok" for v in mod_status.values())
    return 0 if ok else 1


def _load_scope(scope_path: str) -> "SurfaceScope":
    from agents.surface_discovery import SurfaceScope
    path = Path(scope_path)
    if not path.is_file():
        raise SystemExit(f"scope file not found: {scope_path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    return SurfaceScope.from_mapping(data)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="surfaceforge", description="SurfaceForge SRC automation CLI")
    sub = p.add_subparsers(dest="command", required=True)

    w = sub.add_parser("webui", help="Start the WebUI server")
    w.add_argument("--port", type=int, default=None)
    w.add_argument("--state-dir", default=None)
    w.set_defaults(func=cmd_webui)

    s = sub.add_parser("scan", help="Surface discovery only")
    s.add_argument("url")
    s.add_argument("--scope", required=True)
    s.add_argument("--out-dir", default="./out")
    s.add_argument("--max-scripts", type=int, default=40)
    s.set_defaults(func=cmd_scan)

    a = sub.add_parser("agent", help="LLM agent loop on existing blackboard")
    a.add_argument("blackboard")
    a.add_argument("--scope", required=True)
    a.add_argument("--max-cycles", type=int, default=20)
    a.add_argument("--reasoner-prefer", default="deepseek")
    a.set_defaults(func=cmd_agent)

    au = sub.add_parser("auto", help="Full pipeline: scan → agent")
    au.add_argument("url")
    au.add_argument("--scope", required=True)
    au.add_argument("--out-dir", default="./out")
    au.add_argument("--max-cycles", type=int, default=20)
    au.add_argument("--reasoner-prefer", default="deepseek")
    au.set_defaults(func=cmd_auto)

    pr = sub.add_parser("progress", help="Show test progress summary")
    pr.add_argument("--state-dir", default=None)
    pr.set_defaults(func=cmd_progress)

    ss = sub.add_parser("sessions", help="List past SRC sessions")
    ss.add_argument("--state-dir", default=None)
    ss.set_defaults(func=cmd_sessions)

    rs = sub.add_parser("resume", help="Resume an SRC session's agent loop")
    rs.add_argument("session_id")
    rs.add_argument("--scope", required=True)
    rs.add_argument("--max-cycles", type=int, default=20)
    rs.add_argument("--reasoner-prefer", default="deepseek")
    rs.add_argument("--state-dir", default=None)
    rs.set_defaults(func=cmd_resume)

    d = sub.add_parser("doctor", help="Environment check")
    d.set_defaults(func=cmd_doctor)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except SystemExit:
        raise
    except Exception as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
