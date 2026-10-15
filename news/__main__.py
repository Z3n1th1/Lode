import argparse
import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "summarize":
        from .summarizer import main as summarize_main
        return summarize_main(sys.argv[1:])
    if len(sys.argv) > 1 and sys.argv[1] == "digest":
        parser = argparse.ArgumentParser(description="Pulse incremental two-hour news digest")
        parser.add_argument("digest", choices=["digest"])
        parser.add_argument("--registry", required=True, type=Path)
        parser.add_argument("--state-dir", required=True, type=Path)
        parser.add_argument("--feishu", action="store_true", help="send one digest to the configured Feishu bot")
        parser.add_argument("--dry-run", action="store_true", help="fetch and preview without changing state or sending")
        parser.add_argument("--env-file", type=Path,
                            help="isolated news credentials file (default: project .env.news.local)")
        parser.add_argument("--timeout", type=float, default=8)
        args = parser.parse_args()
        try:
            from .channels import load_news_environment
            from .digest import run_digest
            load_news_environment(args.env_file or Path(__file__).resolve().parents[1] / ".env.news.local",
                                  optional=args.env_file is None)
            result = run_digest(args.registry, args.state_dir, feishu=args.feishu,
                                dry_run=args.dry_run, timeout=args.timeout)
        except Exception as exc:
            print(json.dumps({"ok": False, "error": type(exc).__name__}), flush=True)
            return 1
        print(json.dumps(result, ensure_ascii=False), flush=True)
        return 0 if result["ok"] else 1
    parser = argparse.ArgumentParser(description="Pulse public news pipeline")
    parser.add_argument("command", choices=["run"])
    parser.add_argument("--registry", required=True, type=Path)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--no-ai", action="store_true")
    parser.add_argument("--allow-missing-ai", action="store_true",
                        help="collect with source summaries when DEEPSEEK_API_KEY is absent")
    parser.add_argument("--feishu", action="store_true")
    parser.add_argument("--discord", action="store_true")
    parser.add_argument("--dry-run", action="store_true",
                        help="preview source summaries without AI requests, notifications, or delivery-state changes")
    parser.add_argument("--env-file", type=Path,
                        help="isolated news credentials file (default: project .env.news.local)")
    parser.add_argument("--max-ai-items", type=int, default=5)
    parser.add_argument("--max-messages", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=8)
    args = parser.parse_args()
    from .pipeline import run_cycle
    try:
        from .channels import load_news_environment
        load_news_environment(args.env_file or Path(__file__).resolve().parents[1] / ".env.news.local",
                              optional=args.env_file is None)
        result = run_cycle(args.registry, args.state_dir, no_ai=args.no_ai,
                           allow_missing_ai=args.allow_missing_ai, feishu=args.feishu,
                           discord=args.discord, dry_run=args.dry_run,
                           max_ai_items=args.max_ai_items, max_messages=args.max_messages,
                           timeout=args.timeout)
    except Exception as exc:
        print(json.dumps({"ok": False, "error": type(exc).__name__}), flush=True)
        return 1
    print(json.dumps(result, ensure_ascii=False), flush=True)
    return 0 if result["ok"] else 1


raise SystemExit(main())
