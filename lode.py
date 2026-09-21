#!/usr/bin/env python3
"""Lode unified CLI — cross-platform entry point.

Works identically on Windows / Linux / macOS. Auto-loads .env for API keys.

Usage:
  python lode.py console                 # start the Console
  python lode.py scan <url>            # surface discovery only
  python lode.py agent <blackboard>    # LLM agent loop on existing blackboard
  python lode.py auto <url>            # full: scan → agent → report
  python lode.py progress              # show test progress summary
  python lode.py doctor                # environment check
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

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


def _prefer(args: argparse.Namespace, attr: str, env_name: str, default: str = "") -> str:
    """CLI flag wins, else the env default set by the Console settings file."""
    value = getattr(args, attr, None)
    if value:
        return str(value)
    return os.environ.get(env_name, "").strip() or default


def _run_agent(blackboard: str, scope_path: str, args: argparse.Namespace,
               budget: object = None) -> dict:
    from agents.src_agent import run_src_agent

    scope = _load_scope(scope_path)
    return run_src_agent(
        blackboard, scope,
        max_cycles=args.max_cycles,
        reasoner_prefer=_prefer(args, "reasoner_prefer", "SRC_REASONER_PREFER", "deepseek"),
        explorer_prefer=_prefer(args, "explorer_prefer", "SRC_EXPLORER_PREFER"),
        request_budget=budget,
    )


def cmd_console(args: argparse.Namespace) -> int:
    """Start the Console server."""
    port = str(args.port or os.environ.get("LODE_PORT", "8088"))
    state_dir = args.state_dir or os.environ.get("LODE_STATE_DIR", str(ROOT / "lode-state"))
    cmd = [
        _python(), "-m", "console.server",
        "--state-dir", state_dir,
        "--static-dir", str(ROOT / "console" / "dist"),
        "--port", port,
    ]
    return subprocess.call(cmd, cwd=str(ROOT))


def _target_slug(url: str) -> str:
    """Per-target subdirectory name, so a batch does not overwrite itself."""
    netloc = urlsplit(url).netloc or urlsplit("//" + url).netloc
    return re.sub(r"[^A-Za-z0-9._-]", "_", netloc).strip("._") or "target"


def _batch_targets(args: argparse.Namespace) -> list[str]:
    """The targets for this invocation.

    A batch used to exist only in the Console (paste a list, one job per asset);
    the CLI took a single url, so running a whole scope from the command line
    meant writing a shell loop around it — and that loop bypassed the scope
    gate, the delay and the evidence files.  The loop lives in the product now:
    every target still goes through ``discover_surface`` one by one.
    """
    if getattr(args, "targets_file", None):
        lines = Path(args.targets_file).read_text(encoding="utf-8").splitlines()
        targets = [line.strip() for line in lines]
        targets = [t for t in targets if t and not t.startswith("#")]
    elif getattr(args, "from_scope", False):
        doc = json.loads(Path(args.scope).read_text(encoding="utf-8"))
        targets = [str(u).strip() for u in (doc.get("seed_urls") or []) if str(u).strip()]
        if not targets:
            targets = ["https://" + str(h).strip().lstrip("*.") + "/"
                       for h in (doc.get("allowed_hosts") or []) if str(h).strip()]
    else:
        targets = [args.url] if getattr(args, "url", None) else []
    if not targets:
        raise SystemExit("no targets: pass a url, --targets-file or --from-scope")
    return targets


def cmd_scan(args: argparse.Namespace) -> int:
    """Surface discovery + candidate triage, one or many targets."""
    from agents.surface_discovery import SurfaceScope, discover_surface, surface_to_dict, write_surface_outputs
    scope = _load_scope(args.scope)
    root = Path(args.out_dir)
    root.mkdir(parents=True, exist_ok=True)
    targets = _batch_targets(args)
    batch = len(targets) > 1
    rows = []
    for target in targets:
        # Single target keeps writing straight into --out-dir (the shape callers
        # already have); a batch gets one subdirectory per host.
        out_dir = root / _target_slug(target) if batch else root
        out_dir.mkdir(parents=True, exist_ok=True)
        print(f"[scan] {target}", file=sys.stderr)
        try:
            result = discover_surface(scope, target, max_scripts=args.max_scripts)
        except (ValueError, OSError, TypeError) as exc:
            rows.append({"target": target, "status": 0, "error": str(exc)})
            continue
        d = surface_to_dict(result)
        json_path, md_path = write_surface_outputs(result, out_dir)
        rows.append({
            "target": target,
            "status": d["status"],
            "final_url": d["final_url"],
            "paths": len(d["paths"]),
            "api_urls": len(d["api_urls"]),
            "scripts": len(d["scripts"]),
            "fingerprints": d["fingerprints"][:8],
            "output_json": str(json_path),
            "output_md": str(md_path),
            "errors": d["errors"][:5],
        })
        if args.console_state:
            # 落盘只是一半:Console 只读 state_dir 里的台账,不看 --out-dir。
            # 不记这一行,跑得再多在界面上也是零。
            from console.task_ledger import record_run
            record_run(args.console_state, target=target, output_path=out_dir)
            rows[-1]["recorded_in"] = str(args.console_state)
    print(json.dumps({"schema": "SurfaceScanSummary/v1", "targets": rows},
                     ensure_ascii=False, indent=2))
    # 一个都没成就是错的;只要有一个出结果就算跑过了(其余的在 targets[].status 里)
    return 0 if any(row.get("status") for row in rows) else 1


def cmd_agent(args: argparse.Namespace) -> int:
    """Run the LLM agent loop on an existing blackboard."""
    from core.rate_limit import RequestBudget

    summary = _run_agent(args.blackboard, args.scope, args,
                         budget=RequestBudget(getattr(args, "max_requests", 0) or None))
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


def cmd_auto(args: argparse.Namespace) -> int:
    """Full pipeline: scan → autopilot → LLM agent."""
    from agents.src_autopilot import SrcAutopilot
    from core.rate_limit import RequestBudget

    scope = _load_scope(args.scope)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    # 一份额度贯穿整条流水线:爬虫和 agent 花的是同一笔预算,否则只盖住一半。
    budget = RequestBudget(getattr(args, "max_requests", 0) or None)

    autopilot = SrcAutopilot(
        scope, out_dir / "autopilot-state.json", out_dir,
        max_rounds=3, max_candidates=200, request_budget=budget,
    )
    # ``run_round`` has always taken a sequence — only the entry point was
    # single-target. Batch is now expressible instead of shell-looped outside.
    targets = _batch_targets(args)
    print(f"[1/2] Surface discovery + triage on {len(targets)} target(s) ...", file=sys.stderr)
    autopilot.run_round(targets)

    bb_path = out_dir / "src-blackboard.json"
    print(f"[2/2] LLM agent analysis (max {args.max_cycles} cycles) ...", file=sys.stderr)
    summary = _run_agent(str(bb_path), args.scope, args, budget=budget)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


def cmd_surface_import(args: argparse.Namespace) -> int:
    """Record results that are already on disk into the Console ledger — no network.

    A scan that ran before this bridge existed left its output in ``--out-dir`` and
    nothing in ``state_dir``, so the Console showed none of it.  Re-running the scan
    just to make it visible would re-fetch a third party's production hosts for a
    bookkeeping reason; importing reads what is already there instead.
    """
    from console.task_ledger import load_rows, record_run

    root = Path(args.results_dir)
    found = sorted(root.glob("*/surface-*.json")) + sorted(root.glob("surface-*.json"))
    if not found:
        print(json.dumps({"schema": "SurfaceImportSummary/v1", "imported": 0,
                          "error": f"no surface-*.json under {root}"},
                         ensure_ascii=False, indent=2))
        return 1

    already = {(str(row.get("target") or ""), str(row.get("output_path") or ""))
               for row in load_rows(args.console_state)}
    results = []
    for path in found:
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            results.append({"file": str(path), "skipped": f"unreadable:{exc}"})
            continue
        target = str(doc.get("target") or "").strip()
        if not target:
            results.append({"file": str(path), "skipped": "no_target_in_result"})
            continue
        if (target, str(path.parent.resolve())) in already:
            results.append({"target": target, "skipped": "already_recorded"})
            continue
        run_id = "surface-" + re.sub(r"[^A-Za-z0-9_.-]", "-", path.parent.name or "root")
        row = record_run(args.console_state, target=target, output_path=path.parent, run_id=run_id)
        results.append({"task_id": row["id"], "target": target, "output_path": row["output_path"]})

    imported = [r for r in results if "task_id" in r]
    print(json.dumps({"schema": "SurfaceImportSummary/v1",
                      "console_state": str(args.console_state),
                      "imported": len(imported), "results": results},
                     ensure_ascii=False, indent=2))
    return 0


def cmd_progress(args: argparse.Namespace) -> int:
    """Show test progress summary."""
    from core.test_log import SrcTestLog
    state_dir = Path(args.state_dir or ROOT / "lode-state")
    log = SrcTestLog(state_dir)
    print(json.dumps(log.summary(), ensure_ascii=False, indent=2))
    return 0


def cmd_sessions(args: argparse.Namespace) -> int:
    """List past SRC chat sessions and their state (for resuming)."""
    from core.src_blackboard import SrcBlackboard
    state_dir = Path(args.state_dir or ROOT / "lode-state")
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
    from core.src_blackboard import SrcBlackboard

    state_dir = Path(args.state_dir or ROOT / "lode-state")
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

    summary = _run_agent(str(bb_path), args.scope, args)
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
        "llm_model": os.environ.get("LLM_MODEL", "deepseek-flash"),
        "env_file": (ROOT / ".env").is_file(),
        "console_dist": (ROOT / "console" / "dist" / "index.html").is_file(),
    }
    # Check key modules
    mod_status = {}
    for mod in ("agents.src_agent", "agents.src_chat", "agents.surface_discovery",
                "agents.src_autopilot", "core.src_blackboard", "core.test_log",
                "core.action_admission"):
        try:
            __import__(mod)
            mod_status[mod] = "ok"
        except Exception as exc:
            mod_status[mod] = f"FAIL: {type(exc).__name__}"
    checks["modules"] = mod_status
    # 探测档靠 guardrails 的分类器;它不在时猎手仍能跑,但只能读 —— 所以这条要报出来,
    # 而不是让它悄悄退化。
    try:
        from core.action_admission import classifier_available, classifier_error
        from core.rate_limit import configured_max_requests

        checks["admission_classifier"] = "ok" if classifier_available() else (
            f"unavailable: {classifier_error() or 'unknown'}")
        checks["max_requests_per_run"] = configured_max_requests()
    except Exception as exc:  # noqa: BLE001
        checks["admission_classifier"] = f"FAIL: {type(exc).__name__}"
    print(json.dumps(checks, ensure_ascii=False, indent=2))
    ok = (checks["llm_api_key_set"] and all(v == "ok" for v in mod_status.values())
          and checks.get("admission_classifier") == "ok")
    return 0 if ok else 1


def _load_scope(scope_path: str) -> "SurfaceScope":
    from agents.surface_discovery import SurfaceScope
    path = Path(scope_path)
    if not path.is_file():
        raise SystemExit(f"scope file not found: {scope_path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    return SurfaceScope.from_mapping(data)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="lode", description="Lode SRC automation CLI")
    sub = p.add_subparsers(dest="command", required=True)

    w = sub.add_parser("console", help="Start the Console server")
    w.add_argument("--port", type=int, default=None)
    w.add_argument("--state-dir", default=None)
    w.set_defaults(func=cmd_console)

    s = sub.add_parser("scan", help="Surface discovery only")
    s.add_argument("url", nargs="?")
    s.add_argument("--scope", required=True)
    s.add_argument("--out-dir", default="./out")
    s.add_argument("--max-scripts", type=int, default=40)
    s.add_argument("--targets-file", type=Path,
                   help="file with one target per line (blank lines and # comments skipped)")
    s.add_argument("--from-scope", action="store_true",
                   help="use the scope's seed_urls, else every allowed_hosts entry, as the list")
    s.add_argument("--console-state", type=Path,
                   help="Console state dir; record each run in its task ledger so it shows up in the UI")
    s.set_defaults(func=cmd_scan)

    a = sub.add_parser("agent", help="LLM agent loop on existing blackboard")
    a.add_argument("blackboard")
    a.add_argument("--scope", required=True)
    a.add_argument("--max-cycles", type=int, default=20)
    a.add_argument("--reasoner-prefer", default=None,
                   help="Provider substring for the Reasoner (default: SRC_REASONER_PREFER env)")
    a.add_argument("--explorer-prefer", default=None,
                   help="Provider substring for the Explorer (default: SRC_EXPLORER_PREFER env)")
    a.add_argument("--max-requests", type=int, default=0,
                   help="这一轮最多发几个请求(默认 60,硬顶 120;0 = 用默认)")
    a.set_defaults(func=cmd_agent)

    au = sub.add_parser("auto", help="Full pipeline: scan → agent")
    au.add_argument("url", nargs="?")
    au.add_argument("--scope", required=True)
    au.add_argument("--out-dir", default="./out")
    au.add_argument("--max-cycles", type=int, default=20)
    au.add_argument("--max-requests", type=int, default=0,
                    help="整条流水线最多发几个请求(默认 60,硬顶 120;0 = 用默认)")
    au.add_argument("--reasoner-prefer", default=None)
    au.add_argument("--explorer-prefer", default=None)
    au.add_argument("--targets-file", type=Path,
                    help="file with one target per line (blank lines and # comments skipped)")
    au.add_argument("--from-scope", action="store_true",
                    help="use the scope's seed_urls, else every allowed_hosts entry, as the list")
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
    rs.add_argument("--reasoner-prefer", default=None)
    rs.add_argument("--explorer-prefer", default=None)
    rs.add_argument("--state-dir", default=None)
    rs.set_defaults(func=cmd_resume)

    d = sub.add_parser("doctor", help="Environment check")
    d.set_defaults(func=cmd_doctor)

    si = sub.add_parser("surface-import",
                        help="Record already-scanned results into the Console task ledger (no network)")
    si.add_argument("results_dir", type=Path,
                    help="an --out-dir from a previous scan (with or without per-target subdirs)")
    si.add_argument("--console-state", type=Path, required=True)
    si.set_defaults(func=cmd_surface_import)

    return p


def _shared_state_dir(args: argparse.Namespace) -> Path:
    """Where the cross-process request budget lives.

    The Console keeps it under its ``--state-dir``; the CLI has to look in the same
    place, or a CLI ``--from-scope`` run and a Console run against one program each
    send at the full stated rate and the program sees the sum of the two.
    """
    explicit = getattr(args, "console_state", None) or getattr(args, "state_dir", None)
    if explicit:
        return Path(explicit)
    return Path(os.environ.get("LODE_STATE_DIR") or (ROOT / "lode-state"))


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        from core.rate_limit import configure_persistence

        configure_persistence(_shared_state_dir(args))
    except Exception:  # noqa: BLE001 - pacing is enforced per process even if this fails
        pass
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
