"""One request budget per engagement, shared by every worker that draws on it.

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
This shares across **threads in one process**, and — once a state dir is
configured (:func:`configure_persistence`) — across **processes** too, by keeping
the engagement's token state in a file under that state dir.  Two Lode processes
against one program used to each run their own budget, so the program saw the sum
of the two; that is the case the file bucket closes, and it is the reason a CLI
``--from-scope`` run and a Console run can no longer be added together.

The configurable file bucket is opt-in on purpose: leave the state dir unset
(tests, library use) and this module behaves exactly as it did before, with the
in-process bucket only.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlsplit

try:
    from core.file_lock import AdvisoryFileLock
except ImportError:  # pragma: no cover - flat sys.path (tests insert core/ directly)
    from file_lock import AdvisoryFileLock  # type: ignore

__all__ = ["TokenBucket", "FileTokenBucket", "ScopeLimiter", "limiter_for",
           "reset_limiters", "configure_persistence", "bucket_key",
           "RequestBudget", "configured_max_requests"]


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


class FileTokenBucket:
    """The same contract as :class:`TokenBucket`, with the state on disk.

    One process's registry only knows its own threads, so "the budget" was really
    "this process's share of the budget": a CLI run and a Console run against the
    same program each sat at the full stated rate and the program saw double.
    Putting the token state in a file under the state dir — read-modify-written
    under an advisory lock — makes the process boundary stop mattering.

    Two deliberate differences from the in-memory bucket:

    * the clock is ``time.time()``, not ``time.monotonic()``, because two
      processes have to agree on how much time passed;
    * the state is persisted on *every* attempt, including the ones that fail to
      take a token, so a waiter's refill is never recomputed from a stale
      timestamp.
    """

    def __init__(self, path: Path, *, rate_per_second: float, capacity: float = 1.0,
                 key: str = "") -> None:
        self.path = Path(path)
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        self.rate = max(1e-6, float(rate_per_second))
        self.capacity = max(1.0, float(capacity))
        # 桶的键只为了让人能打开文件知道这是谁的预算 —— 桶本身不认识 engagement。
        self.key = key or self.path.stem

    def acquire(self) -> None:
        while True:
            wait = self._try_take()
            if wait <= 0:
                return
            # 睡在锁外面 —— 和内存桶同一条理由:在锁里等就把所有 worker 串成队列。
            # 加个下限,免得令牌只差千分之几个时变成自旋。
            time.sleep(max(0.002, wait))

    def _try_take(self) -> float:
        """Return 0.0 when a token was spent, else how long to wait before retrying."""
        with AdvisoryFileLock(self.lock_path):
            state = self._read()
            now = time.time()
            tokens = min(self.capacity, state["tokens"] + (now - state["updated_at"]) * self.rate)
            if tokens >= 1.0:
                self._write(now, tokens - 1.0)
                return 0.0
            self._write(now, tokens)
            return (1.0 - tokens) / self.rate

    def _read(self) -> Dict[str, Any]:
        try:
            doc = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            doc = None
        if isinstance(doc, dict):
            try:
                return {"tokens": float(doc["tokens"]), "updated_at": float(doc["updated_at"])}
            except (KeyError, TypeError, ValueError):
                pass
        # 没有文件(第一次请求)或者文件坏了:按满桶起步,和内存桶的初值一致,
        # 所以"第一个请求是免费的"这条在两个实现里是同一件事。
        return {"tokens": self.capacity, "updated_at": time.time()}

    def _write(self, updated_at: float, tokens: float) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"key": self.key, "tokens": round(tokens, 6), "updated_at": updated_at,
                   "rate_per_second": self.rate, "capacity": self.capacity}
        self.path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


class ScopeLimiter:
    """The engagement-wide bucket plus one bucket per host."""

    def __init__(self, engagement: str, *, rate_per_second: float,
                 state_dir: Optional[Path] = None) -> None:
        self.engagement = engagement
        self.rate_per_second = float(rate_per_second)
        self.state_dir = Path(state_dir) if state_dir else None
        # 程序桶是"所有流量 <= N req/s"那句承诺,所以它必须跨进程 —— 有 state dir
        # 就落到文件上。主机桶只是礼貌(politeness),留在进程内:它是同一条承诺
        # 的窄化,不是第二句承诺,而且每个 host 一个文件会让超大 scope 写爆目录。
        self._program: Any = (
            FileTokenBucket(_budget_path(self.state_dir, engagement),
                            rate_per_second=self.rate_per_second, key=engagement)
            if self.state_dir is not None else TokenBucket(self.rate_per_second)
        )
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


def bucket_key(scope: Any) -> str:
    """Which engagement's promise this scope is making.  One bucket per value.

    ``engagement`` is the budget identity; ``program`` is only its fallback.
    They differ on the Console path, where every job mints its own program name
    (``console-<run_id>``) — using that as the key gave each job its own bucket, so
    pasting 20 targets ran 20 independent budgets and the program saw 20× its
    stated rate.  A scope file never sets ``engagement``, so the CLI keeps the
    exact key it had.
    """
    engagement = str(getattr(scope, "engagement", "") or "").strip()
    return engagement or str(getattr(scope, "program", "") or "authorized-program").strip()


def _budget_path(state_dir: Path, key: str) -> Path:
    """One file per engagement.  Hashed so a program name can't escape the dir."""
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
    return Path(state_dir) / "rate-limit" / f"{digest}.json"


_LIMITERS: Dict[Tuple[str, float], ScopeLimiter] = {}
_LIMITERS_GUARD = threading.Lock()
_STATE_DIR: Optional[Path] = None


def configure_persistence(state_dir: Any) -> None:
    """Make the budget shared with other processes, via ``state_dir``.

    Called once at start-up by the Console and the CLI, both of which already
    know their state dir.  Passing ``None``/``""`` goes back to the in-process
    bucket (what tests and library use get).

    Existing limiters are dropped: they were built with the old answer to "is
    there a file to share?", and handing back a cached in-process limiter after
    this call would silently keep the two processes apart.
    """
    global _STATE_DIR
    _STATE_DIR = Path(state_dir) if state_dir else None
    reset_limiters()


def limiter_for(scope: Any) -> Optional[ScopeLimiter]:
    """The bucket every worker of this scope must draw from, or ``None`` if unpaced.

    Keyed by ``(engagement, delay)`` and not by engagement alone: two scopes that
    declare different pacing are two different promises, and collapsing them
    would silently apply the first one's rate to the second.  It also keeps
    tests that reuse a fixture program name from inheriting each other's state.
    """
    delay = float(getattr(scope, "delay_seconds", 0.0) or 0.0)
    if delay <= 0:
        return None
    key = (bucket_key(scope), round(delay, 6))
    with _LIMITERS_GUARD:
        limiter = _LIMITERS.get(key)
        if limiter is None:
            limiter = ScopeLimiter(key[0], rate_per_second=1.0 / delay, state_dir=_STATE_DIR)
            _LIMITERS[key] = limiter
        return limiter


def reset_limiters() -> None:
    """Drop every bucket.  Tests only — pacing state must not leak between runs."""
    with _LIMITERS_GUARD:
        _LIMITERS.clear()


# ---------------------------------------------------------------------------
# How many requests a run may make, in total
# ---------------------------------------------------------------------------

#: 一轮最多发多少个请求。这不是性能旋钮,是红线要求的边:平台规则写的是
#: "禁止使用扫描器或自动化工具批量探测……禁止产生大量数据流量",而速率桶管的是**多快**,
#: 管不了**多少** —— 在加这个之前,单目标只受速率约束,理论上是 20 圈 × (3 次探索 +
#: 3 个动作 × 2 轮) ≈ 420 个请求。60 是那个数的约七分之一。
MAX_REQUESTS_PER_RUN = 60
HARD_MAX_REQUESTS_PER_RUN = 120
REQUESTS_ENV = "LODE_MAX_REQUESTS_PER_RUN"


def configured_max_requests() -> int:
    """一轮的请求上限,可被 ``LODE_MAX_REQUESTS_PER_RUN`` 覆盖并夹在硬顶内。

    非数字、``0`` 和负数一律回落到缺省:一个写坏的配置不该变成"没有上限",也不该变成
    "上限 1"(那会让每一轮都一无所获却看不出原因)。``0 = 用默认`` 也是 CLI 的说法。
    """
    raw = os.environ.get(REQUESTS_ENV, "").strip()
    if not raw:
        return MAX_REQUESTS_PER_RUN
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return MAX_REQUESTS_PER_RUN
    if value <= 0:
        return MAX_REQUESTS_PER_RUN
    return min(value, HARD_MAX_REQUESTS_PER_RUN)


class RequestBudget:
    """一轮的请求计数。线程安全。

    和速率桶是两件互补的事,别合并:

    * :func:`limiter_for` 的桶盖住**多快** —— 它是跨进程共享的,按 engagement 算,
      所以 N 个 worker 合计不会超过文档写的那条 req/s。
    * 这个类盖住**多少** —— 每次运行一份,不跨进程。

    计数点放在**准入之后、限速之前**:治理拒掉的请求不该消耗操作员的额度,而额度用完
    的运行应该立刻返回,不该先睡在一个令牌上再发现没得发了。
    """

    def __init__(self, limit: Optional[int] = None) -> None:
        self.limit = int(limit) if limit else configured_max_requests()
        self._used = 0
        self._lock = threading.Lock()

    @property
    def used(self) -> int:
        with self._lock:
            return self._used

    @property
    def remaining(self) -> int:
        with self._lock:
            return max(0, self.limit - self._used)

    @property
    def exhausted(self) -> bool:
        with self._lock:
            return self._used >= self.limit

    def spend(self) -> bool:
        """Take one request's worth.  ``False`` once the run is out."""
        with self._lock:
            if self._used >= self.limit:
                return False
            self._used += 1
            return True
