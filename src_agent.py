"""CLI for LLM-driven SRC agent loop."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# Auto-load .env for API keys
try:
    from core.config import load_dotenv
    load_dotenv()
except Exception:
    pass

from agents.src_agent import run_src_agent
from agents.surface_discovery import SurfaceScope


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lode-src-agent",
        description="LLM-driven SRC agent: reads blackboard candidates, reasons about vulnerabilities, explores endpoints",
    )
    parser.add_argument("--scope", required=True, type=Path,
                        help="Scope JSON file with authorization and allowed domains")
    parser.add_argument("--blackboard", required=True, type=Path,
                        help="Path to src-blackboard.json (created by src_autopilot)")
    parser.add_argument("--max-cycles", type=int, default=20,
                        help="Maximum reason→explore cycles (default: 20)")
    parser.add_argument("--max-explore", type=int, default=3,
                        help="Maximum intents to explore per cycle (default: 3)")
    parser.add_argument("--reasoner-prefer", type=str, default="deepseek",
                        help="Preferred LLM provider for Reasoner (default: deepseek)")
    parser.add_argument("--explorer-prefer", type=str, default="",
                        help="Preferred LLM provider for Explorer (default: any)")
    parser.add_argument("--worker-id", type=str, default="",
                        help="Worker ID for blackboard claims")
    parser.add_argument("--timeout", type=float, default=60.0,
                        help="LLM call timeout in seconds (default: 60)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        scope_data = json.loads(args.scope.read_text(encoding="utf-8"))
        scope = SurfaceScope.from_mapping(scope_data)
        summary = run_src_agent(
            args.blackboard,
            scope,
            max_cycles=args.max_cycles,
            max_explore_per_cycle=args.max_explore,
            reasoner_prefer=args.reasoner_prefer,
            explorer_prefer=args.explorer_prefer,
            worker_id=args.worker_id,
            timeout=args.timeout,
        )
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError, RuntimeError) as exc:
        print(json.dumps({"schema": "SrcAgentError/v1", "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
