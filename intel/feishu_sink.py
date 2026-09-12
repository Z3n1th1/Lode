from __future__ import annotations

from pathlib import Path
from typing import Any

from .models import RunReport


def send_report(
    report: RunReport,
    *,
    program: str,
    store_root: str | Path,
    webhook: str = "",
    secret: str = "",
    dry_run: bool = False,
    min_score: float = 60.0,
    max_items: int = 5,
) -> dict[str, Any]:
    """Send a redacted new-asset digest through the existing one-way Feishu notifier."""
    candidates = [
        item for item in report.candidates
        if item.is_new and item.score >= float(min_score) and item.scope_status == "in_scope"
    ][: max(1, min(int(max_items), 20))]
    if not candidates:
        return {"ok": True, "skipped": "no_new_candidates"}
    try:
        from notify.feishu_notifier import NotifyEvent, Throttler, notify
    except Exception as exc:  # optional channel; collection must stay usable without it
        return {"ok": False, "error": f"feishu_adapter_unavailable:{exc.__class__.__name__}"}
    lines = []
    for item in candidates:
        title = (item.title or item.value).replace("\n", " ")[:120]
        summary = item.summary.replace("\n", " ")[:220]
        line = f"{title} · {item.value} · score={item.score:.0f} · source={item.source}"
        if summary and summary != title:
            line += f"\n摘要: {summary}"
        lines.append(line)
    event = NotifyEvent(
        level="P2",
        title=f"{program} 公开安全情报新增 {len(candidates)} 条",
        body="\n".join(lines),
        target=program,
        evidence_ref="",
    )
    throttler = Throttler(Path(store_root) / "feishu-throttle.json")
    return notify(event, webhook=webhook, secret=secret, throttler=throttler, dry_run=dry_run)
