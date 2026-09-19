"""One request budget per engagement, shared by every worker in the process.

Why this exists
---------------
``SurfaceScope.delay_seconds`` used to be enforced by each call site sleeping on
its own clock (``agents/surface_discovery.py`` and ``agents/src_agent.py`` each
kept a ``last_request`` of their own).  That is a **per-worker** pace, not a
per-engagement one: run two workers and the program sees twice the requests, run
eight and it sees eight times.  So "add workers" and "keep the stated req/s" were
mutually exclusive, and the only legal way to go faster was to stay slow.

A pace belongs to the engagement, not to the worker.  One bucket per scope, held
in a module-level registry, is what lets fan-out be both faster *and* legal:
while one worker waits on the model, another spends a token.  The ceiling does
not move — the pipe stops idling.

Two ceilings, deliberately:

* the **program** bucket is the contract ("all traffic <= N req/s overall");
* the **host** bucket is the older, narrower promise — it stops one host from
  absorbing the whole budget while forty others wait.

Both are derived from ``delay_seconds`` today, so a single worker behaves exactly
as it did before (the host bucket is the old sleep) while N workers now share one
program budget instead of N of them.

``delay_seconds <= 0`` means the scope declared no pacing; this whole module then
stays out of the way, which keeps the zero-delay fixtures instant.

Scope of the guarantee
----------------------
This shares across **threads in one process**.  Two separate Lode processes
against the same program do not share a budget yet — that needs the bucket state
in a file under the state dir (``core/file_lock.AdvisoryFileLock`` is the right
primitive), and it only starts to matter once workers are separate processes.
Until then, don't run two Lode processes against one program and expect the
stated rate to hold.
"""
from __future__ import annotations

import threading
import time
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlsplit

__all__ = ["TokenBucket", "ScopeLimiter", "limiter_for", "reset_limiters"]


class TokenBucket:
    """A rate in tokens/second, with a small burst allowance.

    ``capacity`` is deliberately 1 by default: a burst above one is exactly what
    a per-request rate limit is supposed to prevent, so it has to be asked for
    explicitly.
    """

    def __init__(self, rate_per_second: float, capacity: float = 1.0) -> None:
        self.rate = max(1e-6, float(rate_per_second))
        self.capacity = max(1.0, float(capacity))
        self._tokens = self.capacity
        self._updated = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        """Block until one token is available, then spend it."""
        while True:
            with self._lock:
                now = time.monotonic()
                self._tokens = min(
                    self.capacity, self._tokens + (now - self._updated) * self.rate
                )
                self._updated = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                wait = (1.0 - self._tokens) / self.rate
            # 睡在锁外面:在锁里 sleep 会把所有 worker 串成一条队,桶就退化成
            # 全局串行,并发度再高也只是排队等一个人。
            time.sleep(wait)


class ScopeLimiter:
    """The engagement-wide bucket plus one bucket per host."""

    def __init__(self, program: str, *, rate_per_second: float) -> None:
        self.program = program
        self.rate_per_second = float(rate_per_second)
        self._program = TokenBucket(self.rate_per_second)
        self._hosts: Dict[str, TokenBucket] = {}
        self._guard = threading.Lock()

    def _host_bucket(self, host: str) -> TokenBucket:
        with self._guard:
            bucket = self._hosts.get(host)
            if bucket is None:
                bucket = TokenBucket(self.rate_per_second)
                self._hosts[host] = bucket
            return bucket

    def acquire(self, url: str) -> None:
        """Block until this request may be sent.  Host first, then program.

        先窄后宽:先在主机桶上等,再花程序桶的令牌。反过来的话,一个被主机桶
        卡住的 worker 会攥着一枚全程序共享的令牌睡觉 —— 那枚令牌本来可以让另
        一个 worker 去请求别的主机。顺序错了,并发就白加了。
        """
        host = (urlsplit(url).hostname or "").lower()
        if host:
            self._host_bucket(host).acquire()
        self._program.acquire()


_LIMITERS: Dict[Tuple[str, float], ScopeLimiter] = {}
_LIMITERS_GUARD = threading.Lock()


def limiter_for(scope: Any) -> Optional[ScopeLimiter]:
    """The bucket every worker of this scope must draw from, or ``None`` if unpaced.

    Keyed by ``(program, delay)`` and not by program alone: two scopes that
    declare different pacing are two different promises, and collapsing them
    would silently apply the first one's rate to the second.  It also keeps
    tests that reuse a fixture program name from inheriting each other's state.
    """
    delay = float(getattr(scope, "delay_seconds", 0.0) or 0.0)
    if delay <= 0:
        return None
    program = str(getattr(scope, "program", "") or "authorized-program")
    key = (program, round(delay, 6))
    with _LIMITERS_GUARD:
        limiter = _LIMITERS.get(key)
        if limiter is None:
            limiter = ScopeLimiter(program, rate_per_second=1.0 / delay)
            _LIMITERS[key] = limiter
        return limiter


def reset_limiters() -> None:
    """Drop every bucket.  Tests only — pacing state must not leak between runs."""
    with _LIMITERS_GUARD:
        _LIMITERS.clear()
