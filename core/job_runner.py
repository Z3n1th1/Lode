"""Bounded worker pool that runs durable :mod:`core.job_registry` jobs.

Replaces the Console's ``threading.Thread(daemon=True)`` background run. A pool of
``LODE_JOB_WORKERS`` workers (default 8) executes jobs concurrently; job state is on
disk so a restart never loses the record, and the worker re-checks the durable
``stop_requested`` flag at every phase boundary so a stop is cooperative.

Absorbed from the old (unwired) ``core.orchestrator``: phase retry with linear
backoff, a simple request/time budget, ``waiting_approval`` releasing the worker,
and fail-closed error handling.
"""
from __future__ import annotations

import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, Optional

from core import job_registry as jr
from core.rate_limit import RequestBudget

# kind -> handler(job, ctx) -> result dict (may include "summary_ref", "progress")
Handler = Callable[[jr.JobRecord, "JobContext"], Optional[Dict[str, Any]]]

JOB_WORKERS_ENV = "LODE_JOB_WORKERS"
DEFAULT_JOB_WORKERS = 8
MAX_JOB_WORKERS = 64
#: Job payload key that overrides the per-run request cap for one job.
MAX_REQUESTS_KEY = "max_requests"


def _job_request_limit(job: jr.JobRecord) -> Optional[int]:
    """The payload's ``max_requests`` if it is a usable number, else ``None``.

    ``None`` lets :class:`RequestBudget` fall back to the configured default, which is
    also what a garbage value gets — a mistyped cap must not mean "no cap".
    """
    payload = getattr(job, "payload", None)
    if not isinstance(payload, dict):
        return None
    raw = payload.get(MAX_REQUESTS_KEY)
    if raw is None or raw == "":
        return None
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def configured_job_workers() -> int:
    """How many jobs may be in flight at once.

    The pool is what turns "n targets queued" into "n things actually running".  It
    was hardcoded to 2, so pasting a 250-host scope ran two hosts at a time and
    queued the other 248 regardless of what the scope said.

    Raising it is only *safe* because request pacing is one bucket per scope
    (``core.rate_limit``) instead of one clock per worker.  Without that, N workers
    would send N times the requests the program agreed to — so if you ever bypass
    the limiter, put this back to 1 before you do.
    """
    raw = os.environ.get(JOB_WORKERS_ENV, "").strip()
    if not raw:
        return DEFAULT_JOB_WORKERS
    try:
        return max(1, min(int(raw), MAX_JOB_WORKERS))
    except (TypeError, ValueError):
        return DEFAULT_JOB_WORKERS



class JobContext:
    """Everything a handler needs to report progress and stay cooperative."""

    def __init__(self, runner: "JobRunner", job: jr.JobRecord) -> None:
        self._runner = runner
        self._job = job
        self._stop = threading.Event()
        # 这一轮还能发多少请求。以前只有一个 ``self.requests += 1`` 自增,零调用者 ——
        # 等于没有上限,单目标的请求数只受速率约束。平台红线要求"最小化",所以计数要
        # 真的挡住东西(见 core.rate_limit.RequestBudget)。
        self.budget = RequestBudget(_job_request_limit(job))

    @property
    def job(self) -> jr.JobRecord:
        return self._job

    def emit(self, event_kind: str, **payload: Any) -> None:
        if self._runner.on_event is not None:
            self._runner.on_event(self._job.session_id, event_kind,
                                  {"job_id": self._job.job_id,
                                   "turn_id": self._job.turn_id, **payload})

    def progress(self, **fields: Any) -> None:
        merged = {**self._job.progress, **fields}
        updated = self._runner.registry.update(self._job.job_id, progress=merged)
        if updated is not None:
            self._job = updated

    def stopped(self) -> bool:
        """True once a stop was requested (also flips on in-process shutdown)."""
        if self._stop.is_set():
            return True
        return self._runner.registry.stop_requested(self._job.job_id)

    def cancel(self) -> None:
        self._stop.set()

    def spend_request(self) -> bool:
        """One request against this job's budget.  ``False`` once it is spent."""
        return self.budget.spend()


class JobRunner:
    def __init__(self, *, registry: jr.JobRegistry, handlers: Optional[Dict[str, Handler]] = None,
                 on_event: Optional[Callable[[str, str, Dict[str, Any]], None]] = None,
                 notify_fn: Optional[Callable[[str, str], None]] = None,
                 max_workers: Optional[int] = None, max_phases: int = 3,
                 retry_backoff: float = 1.5) -> None:
        self.registry = registry
        self.handlers: Dict[str, Handler] = dict(handlers or {})
        self.on_event = on_event
        self.notify_fn = notify_fn
        self.max_phases = max(1, max_phases)
        self.retry_backoff = retry_backoff
        # 显式传值优先,没传才看环境变量 —— 测试要能钉死一个确定的并发度,
        # 否则它会跟着操作员的 LODE_JOB_WORKERS 变。
        self.max_workers = max(1, int(max_workers)) if max_workers else configured_job_workers()
        self._pool = ThreadPoolExecutor(max_workers=self.max_workers,
                                        thread_name_prefix="lode-job")
        self._contexts: Dict[str, JobContext] = {}
        self._lock = threading.Lock()
        self._shutdown = False

    # -- public --------------------------------------------------------------
    def submit(self, job: jr.JobRecord) -> None:
        if self._shutdown:
            raise RuntimeError("job_runner_shutdown")
        self.registry.update(job.job_id, status=jr.QUEUED, owner_pid=0)
        self._pool.submit(self._run, job.job_id)

    def stop(self, job_id: str) -> None:
        self.registry.request_stop(job_id)
        with self._lock:
            ctx = self._contexts.get(job_id)
        if ctx is not None:
            ctx.cancel()

    def stop_all(self) -> None:
        for record in self.registry.list(limit=0, active_only=True):
            self.stop(record.job_id)

    def shutdown(self, *, wait: bool = False) -> None:
        self._shutdown = True
        self.stop_all()
        self._pool.shutdown(wait=wait)

    def active_count(self) -> int:
        return len(self.registry.list(limit=0, active_only=True))

    # -- worker --------------------------------------------------------------
    def _run(self, job_id: str) -> None:
        job = self.registry.get(job_id)
        if job is None:
            return
        if job.stop_requested:
            self._finish(job_id, jr.FAILED, error="stopped")
            return
        handler = self.handlers.get(job.kind)
        if handler is None:
            self._finish(job_id, jr.FAILED, error=f"no_handler:{job.kind}")
            return

        job = self.registry.update(job_id, status=jr.RUNNING, started_at=time.time(),
                                   owner_pid=os.getpid()) or job
        ctx = JobContext(self, job)
        with self._lock:
            self._contexts[job_id] = ctx
        ctx.emit("subtask_started", job_kind=job.kind, target=job.target, title=job.payload.get("title", ""))
        try:
            last_error = ""
            for phase in range(self.max_phases):
                if ctx.stopped():
                    self._finish(job_id, jr.FAILED, error="stopped")
                    return
                try:
                    result = handler(ctx.job, ctx) or {}
                except Exception as exc:  # noqa: BLE001 - fail closed
                    last_error = f"{type(exc).__name__}: {str(exc)[:300]}"
                    if phase < self.max_phases - 1:
                        time.sleep(self.retry_backoff * (phase + 1))
                        continue
                    self._finish(job_id, jr.FAILED, error=last_error)
                    return
                if ctx.stopped():  # a stop arriving mid-handler wins over the result
                    self._finish(job_id, jr.FAILED, error="stopped")
                    return
                self._finish(job_id, jr.COMPLETED,
                             summary_ref=str(result.get("summary_ref") or ""),
                             progress={**ctx.job.progress, **dict(result.get("progress") or {})})
                return
        finally:
            with self._lock:
                self._contexts.pop(job_id, None)

    def _finish(self, job_id: str, status: str, *, error: str = "",
                summary_ref: str = "", progress: Optional[Dict[str, Any]] = None) -> None:
        self.registry.update(job_id, status=status, error=error, summary_ref=summary_ref,
                             **({"progress": progress} if progress is not None else {}))
        record = self.registry.get(job_id)
        kind = "subtask_finished"
        payload = {"job_id": job_id, "status": status}
        if record is not None:
            if self.on_event is not None:
                self.on_event(record.session_id, kind,
                              {**payload, "turn_id": record.turn_id, "error": error})
            if self.notify_fn is not None:
                try:
                    self.notify_fn(job_id, status)
                except Exception:  # noqa: BLE001 - notification must never fail a job
                    pass


__all__ = ["JobRunner", "JobContext", "Handler", "MAX_REQUESTS_KEY"]
