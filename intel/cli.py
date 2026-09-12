from __future__ import annotations

import argparse
import json
import signal
import sys
import threading
from pathlib import Path

from .models import IntelQuery
from .runner import collect, providers_from_registry, run_watch
from .store import IntelStore


def _interval(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("interval must be a number") from exc
    if parsed < 1.0:
        raise argparse.ArgumentTypeError("interval must be at least 1 second")
    return parsed


def _add_collection_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--scope", required=True, type=Path, help="AegisPilot scope.json 或确认后的 TargetCard JSON")
    parser.add_argument("--out-dir", required=True, type=Path, help="持久化 run.json、候选清单和 watch 状态的目录")
    parser.add_argument("--registry", type=Path, help="sources.json 或包含 sources.json 的 state 目录")
    parser.add_argument("--file", action="append", default=[], help="离线 JSON/JSONL/CSV 候选，可重复")
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--max-items", type=int, default=200)
    parser.add_argument("--no-network", action="store_true", help="只运行 seed 和本地 fixture")


def _load_query(path: Path) -> IntelQuery:
    return IntelQuery.from_mapping(json.loads(path.read_text(encoding="utf-8")))


def _provider_factory(args: argparse.Namespace):
    paths = [Path(item) for item in args.file]

    def factory():
        if args.no_network:
            from .providers import FileProvider, SeedProvider
            return [SeedProvider("builtin-seed")] + [FileProvider(path) for path in paths]
        providers = providers_from_registry(args.registry, file_paths=paths)
        return providers

    return factory


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pentest-agent-intel", description="授权 scope 内的被动 SRC 资产情报采集")
    sub = parser.add_subparsers(dest="command", required=True)
    collect_parser = sub.add_parser("collect", help="运行 seed/crt.sh/RSS/page-watch/fixture provider")
    _add_collection_options(collect_parser)
    watch_parser = sub.add_parser("watch", help="长期轮询被动情报；不执行主动扫描或漏洞利用")
    _add_collection_options(watch_parser)
    watch_parser.add_argument("--interval-sec", type=_interval, default=900.0, help="轮询间隔，最小 1 秒；生产建议 15 分钟以上")
    watch_parser.add_argument("--max-runs", type=int, default=0, help="最多运行轮数，0 表示持续运行")
    watch_parser.add_argument("--max-consecutive-errors", type=int, default=5, help="连续全源失败多少轮后停止")
    watch_parser.add_argument("--feishu", action="store_true", help="将新增候选摘要发送到 FEISHU_WEBHOOK")
    watch_parser.add_argument("--feishu-dry-run", action="store_true", help="只打印飞书 payload，不发送网络请求")
    watch_parser.add_argument("--feishu-min-score", type=float, default=60.0)
    watch_parser.add_argument("--feishu-max-items", type=int, default=5)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    query = _load_query(args.scope)
    store = IntelStore(args.out_dir)
    if args.command == "collect":
        providers = list(_provider_factory(args)())
        report = collect(query, providers, timeout=args.timeout, max_items=args.max_items, store=store, registry_path=args.registry)
        print(json.dumps({
            "schema": "IntelRunSummary/v1",
            "run_id": report.run_id,
            "out_dir": str(args.out_dir.resolve()),
            "counts": report.to_dict()["counts"],
            "providers": [item.to_dict() for item in report.provider_status],
            "top_candidates": [item.to_dict() for item in report.candidates[:20]],
        }, ensure_ascii=False, indent=2))
        return 0 if any(item.status == "ok" for item in report.provider_status) else 1
    if args.command != "watch":
        return 2
    if args.max_runs < 0:
        raise SystemExit("--max-runs must be >= 0")
    stop_event = threading.Event()

    def request_stop(signum, frame) -> None:  # type: ignore[no-untyped-def]
        del signum, frame
        stop_event.set()

    previous_handlers = {}
    for sig in (signal.SIGINT, getattr(signal, "SIGTERM", signal.SIGINT)):
        try:
            previous_handlers[sig] = signal.getsignal(sig)
            signal.signal(sig, request_stop)
        except (OSError, ValueError):
            continue
    try:
        def emit(report) -> None:  # type: ignore[no-untyped-def]
            print(json.dumps({
                "schema": "IntelWatchRun/v1",
                "run_id": report.run_id,
                "counts": report.to_dict()["counts"],
                "providers": [item.to_dict() for item in report.provider_status],
                "top_candidates": [item.to_dict() for item in report.candidates[:10]],
            }, ensure_ascii=False), flush=True)
            if args.feishu:
                from .feishu_sink import send_report
                result = send_report(
                    report,
                    program=query.program,
                    store_root=args.out_dir,
                    dry_run=args.feishu_dry_run,
                    min_score=args.feishu_min_score,
                    max_items=args.feishu_max_items,
                )
                if not result.get("ok") or result.get("dry_run"):
                    print(json.dumps({"schema": "FeishuIntelNotify/v1", **result}, ensure_ascii=False), file=sys.stderr, flush=True)

        summary = run_watch(
            query,
            _provider_factory(args),
            store=store,
            interval_sec=args.interval_sec,
            timeout=args.timeout,
            max_items=args.max_items,
            max_runs=args.max_runs,
            max_consecutive_errors=args.max_consecutive_errors,
            stop_event=stop_event,
            registry_path=args.registry,
            on_report=emit,
        )
    except TimeoutError as exc:
        print(json.dumps({"schema": "IntelWatchError/v1", "error": str(exc)}, ensure_ascii=False), flush=True)
        return 2
    finally:
        for sig, handler in previous_handlers.items():
            try:
                signal.signal(sig, handler)
            except (OSError, ValueError):
                pass
    print(json.dumps(summary.to_dict(), ensure_ascii=False), flush=True)
    return 0 if summary.status in {"completed", "stopped"} else 1
