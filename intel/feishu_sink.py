from __future__ import annotations

from pathlib import Path
from typing import Any

from .models import RunReport
from .feishu_outbox import FeishuOutbox


def queue_report(report: RunReport, *, program: str, store_root: str | Path,
                 min_score: float = 60.0) -> None:
    """Durably stage candidates before committing collection history; no network."""
    outbox = FeishuOutbox(store_root)
    with outbox.lock():
        state = outbox.read()
        if outbox.enqueue(state, report, program=program, min_score=float(min_score)):
            outbox.write(state)


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
    """Queue every eligible new candidate, then deliver a bounded pending digest.

    Successful acknowledgements survive restarts. A webhook timeout after remote
    acceptance can still cause a duplicate: Feishu webhooks have no idempotency key.
    Dry runs preview pending/new entries without changing queue or throttle state.
    """
    outbox = FeishuOutbox(store_root)
    if dry_run:
        # Atomic state replacement permits a read-only preview without creating
        # a lock or state directory. The preview is never used to acknowledge.
        return _deliver(outbox, outbox.read(), report, program=program, webhook=webhook,
                        secret=secret, dry_run=True, min_score=min_score, max_items=max_items)
    with outbox.lock():
        return _deliver(outbox, outbox.read(), report, program=program, webhook=webhook,
                        secret=secret, dry_run=False, min_score=min_score, max_items=max_items)


def _deliver(outbox: FeishuOutbox, state: dict[str, Any], report: RunReport, *, program: str,
             webhook: str, secret: str, dry_run: bool, min_score: float, max_items: int) -> dict[str, Any]:
    added = outbox.enqueue(state, report, program=program, min_score=float(min_score))
    if added and not dry_run:
        outbox.write(state)
    batch = outbox.batch(state, program=program, max_items=max(1, min(int(max_items), 20)))
    pending = sum(row["program"] == program for row in state["pending"].values())
    if not batch:
        return {"ok": True, "skipped": "no_pending_candidates", "pending": pending, "sent_items": 0}
    try:
        from notify.feishu_notifier import NotifyEvent, Throttler, notify
    except Exception as exc:  # optional channel; collection must stay usable without it
        return {"ok": False, "error": f"feishu_adapter_unavailable:{exc.__class__.__name__}"}
    event = NotifyEvent(
        level="P2",
        title=f"{program} 公开安全情报新增 {len(batch)} 条",
        body="\n".join(row["line"] for _key, row in batch),
        target=program,
        evidence_ref="",
    )
    throttler = Throttler(outbox.root / "feishu-throttle.json")
    result = notify(event, webhook=webhook, secret=secret, throttler=throttler, dry_run=dry_run)
    sent_items = 0
    if result.get("ok") and not result.get("suppressed") and not dry_run:
        outbox.acknowledge(state, batch)
        outbox.write(state)
        sent_items = len(batch)
    return {**result, "enqueued": added, "sent_items": sent_items,
            "pending": pending - sent_items}
