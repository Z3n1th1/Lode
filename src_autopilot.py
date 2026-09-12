"""CLI for bounded, scope-bound SRC candidate triage."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from agents.src_autopilot import SrcAutopilot
from agents.surface_discovery import SurfaceScope


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pentest-agent-src-autopilot",
        description="在明确授权 scope 内运行有限轮次的 SRC surface 候选分诊",
    )
    parser.add_argument("--scope", required=True, type=Path)
    parser.add_argument("--target", action="append", default=[], help="明确授权的目标，可重复")
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--state-file", type=Path)
    parser.add_argument("--blackboard-file", type=Path, help="黑板 JSON 路径；默认与 state-file 同目录")
    parser.add_argument("--result-file", action="append", default=[], type=Path, help="已有 SrcSurfaceResult JSON，可重复；提供后不发起 GET")
    parser.add_argument("--max-rounds", type=int, default=3)
    parser.add_argument("--max-candidates", type=int, default=100)
    parser.add_argument("--max-no-new-rounds", type=int, default=2)
    parser.add_argument("--max-scripts", type=int, default=40)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        scope = SurfaceScope.from_mapping(json.loads(args.scope.read_text(encoding="utf-8")))
        state_file = args.state_file or args.out_dir / "src-autopilot-state.json"
        agent = SrcAutopilot(
            scope,
            state_file,
            args.out_dir,
            max_rounds=args.max_rounds,
            max_candidates=args.max_candidates,
            max_no_new_rounds=args.max_no_new_rounds,
            max_scripts=args.max_scripts,
            blackboard_path=args.blackboard_file,
        )
        results = [json.loads(path.read_text(encoding="utf-8")) for path in args.result_file]
        summary = agent.run_round(args.target, results=results or None)
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError, RuntimeError) as exc:
        print(json.dumps({"schema": "SrcAutopilotError/v1", "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
