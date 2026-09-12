"""CLI entry point for authorized SRC HTML/JS surface discovery."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agents.surface_discovery import SurfaceScope, discover_surface, write_surface_outputs


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pentest-agent-src-surface", description="授权 SRC 目标的低频 HTML/JS 路由与 API 面提取")
    parser.add_argument("--scope", required=True, type=Path, help="包含 authorization 与 allowed_domains/hosts 的 scope.json")
    parser.add_argument("--target", required=True, help="scope 内的单个 HTTP(S) 目标")
    parser.add_argument("--out-dir", required=True, type=Path, help="JSON/Markdown 结果目录")
    parser.add_argument("--max-scripts", type=int, default=40)
    parser.add_argument("--timeout", type=float, help="覆盖 scope 的单请求超时")
    parser.add_argument("--delay-sec", type=float, help="覆盖 scope 的请求间隔，最小 0.1 秒")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        mapping = json.loads(args.scope.read_text(encoding="utf-8"))
        scope = SurfaceScope.from_mapping(mapping)
        if args.timeout is not None or args.delay_sec is not None:
            from dataclasses import replace
            scope = replace(
                scope,
                timeout_seconds=max(1.0, min(float(args.timeout), 60.0)) if args.timeout is not None else scope.timeout_seconds,
                delay_seconds=max(0.1, min(float(args.delay_sec), 30.0)) if args.delay_sec is not None else scope.delay_seconds,
            )
        result = discover_surface(scope, args.target, max_scripts=args.max_scripts)
        json_path, md_path = write_surface_outputs(result, args.out_dir)
        print(json.dumps({
            "schema": "SrcSurfaceSummary/v1",
            "target": result.target,
            "status": result.status,
            "paths": len(result.paths),
            "api_urls": len(result.api_urls),
            "scripts": len(result.scripts),
            "requests": len(result.requests),
            "json": str(json_path.resolve()),
            "markdown": str(md_path.resolve()),
            "errors": result.errors[:10],
        }, ensure_ascii=False, indent=2))
        return 0 if result.status else 1
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(json.dumps({"schema": "SrcSurfaceError/v1", "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

