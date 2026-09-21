"""Console job service: durable registry + runner + session event sink.

Single place that owns the process-wide :class:`JobRegistry` /
:class:`JobRunner` pair (one per state dir) and routes job lifecycle events into
the session's :class:`EventLog`, so a launched subtask streams inline into the
conversation. Feishu notification on terminal state is best-effort and fully
guarded — it must never fail a job.
"""
from __future__ import annotations

import ipaddress
import json
import os
import secrets
import threading
import time
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from core.file_lock import replace_with_retry
from core.event_log import EventLog
from core.intake_state import IntakeStateError
from core.job_registry import ACTIVE, JobRecord, JobRegistry
from core.job_runner import JobContext, JobRunner
from core.targets import public_target_reason

_LOCK = threading.Lock()
_ENTRIES: Dict[str, Dict[str, Any]] = {}
_NOTIFY_STATE: Dict[str, Any] = {"tried": False, "fn": None}


def session_dir(state_dir: Path | str, session_id: str) -> Path:
    return Path(state_dir) / "src-chat" / session_id


def events_path(state_dir: Path | str, session_id: str) -> Path:
    return session_dir(state_dir, session_id) / "events.jsonl"


def get_log(state_dir: Path | str, session_id: str) -> EventLog:
    return EventLog(events_path(state_dir, session_id))


# -- job handlers ------------------------------------------------------------
def _scope_document(scope: Any, *, run_id: str, reasoner: str = "", explorer: str = "",
                    authorization_id: str = "", authorization_digest: str = "") -> Dict[str, Any]:
    """The persisted authorisation record for one run (``SrcRunScope/v1``).

    It has to be *true*, because it is the only thing a reviewer can read afterwards
    that says what the run was permitted to do. It used to carry the host lists and
    nothing about capabilities, so "was this run allowed to POST?" was unanswerable
    from the record — the answer lived in a constant inside ``src_agent.py``. Same
    for ``engagement``: it is the request budget's identity, and a budget nobody can
    name is a budget nobody can audit.

    ``authorization_id`` / ``authorization_digest`` 只在这条 run 是从一份授权文档
    起的时候才有值,它们把这一次 run 指回那份原文 —— 有名字的授权才审得动。
    """
    return {
        "schema": "SrcRunScope/v1",
        "run_id": run_id,
        "program": scope.program,
        "engagement": str(getattr(scope, "engagement", "") or ""),
        "authorization": scope.authorization,
        "authorization_id": str(authorization_id or ""),
        "authorization_digest": str(authorization_digest or ""),
        "allowed_domains": list(scope.allowed_domains),
        "allowed_hosts": list(scope.allowed_hosts),
        "allowed_methods": list(getattr(scope, "allowed_methods", ()) or ()),
        "allow_request_body": bool(getattr(scope, "allow_request_body", False)),
        # 程序写的就是 req/s;delay 是我们的换算。记录里两个都留,免得事后要反算。
        "requests_per_second": round(float(getattr(scope, "requests_per_second", 0.0) or 0.0), 6),
        "reasoner_prefer": reasoner,
        "explorer_prefer": explorer,
        "created_at": time.time(),
    }


def _run_scope(job: JobRecord, ctx: JobContext, scope: Any, *, run_id: str, target_url: str,
               authorization_id: str = "", authorization_digest: str = "") -> Dict[str, Any]:
    """The work itself: one autopilot round, then the LLM agent loop.

    Split out of the handlers because *which* engagements are allowed is decided
    by the caller (a URL typed into the conversation vs a confirmed TargetCard vs
    one host of a confirmed authorisation document), while what happens
    afterwards is the same.
    """
    from agents.src_agent import run_src_agent
    from agents.src_autopilot import SrcAutopilot
    from core import skills

    state_dir = Path(ctx.job.payload.get("_state_dir") or ".")
    out_dir = state_dir / "src-agent-runs" / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    bb_path = out_dir / "src-blackboard.json"
    reasoner = (job.payload.get("reasoner_prefer") or "").strip() or os.environ.get("SRC_REASONER_PREFER", "").strip()
    explorer = (job.payload.get("explorer_prefer") or "").strip() or os.environ.get("SRC_EXPLORER_PREFER", "").strip()

    try:
        scope_doc = _scope_document(scope, run_id=run_id, reasoner=reasoner, explorer=explorer,
                                    authorization_id=authorization_id,
                                    authorization_digest=authorization_digest)
        staged = out_dir / ".scope.json.tmp"
        staged.write_text(json.dumps(scope_doc, ensure_ascii=False, indent=2), encoding="utf-8")
        replace_with_retry(staged, out_dir / "scope.json")
    except OSError:
        pass

    ctx.emit("subtask_progress", phase="autopilot")
    autopilot = SrcAutopilot(scope, out_dir / "autopilot-state.json", out_dir,
                             max_rounds=3, max_candidates=100, blackboard_path=bb_path,
                             request_budget=ctx.budget)
    autopilot.run_round([target_url])
    if ctx.stopped():
        return {"progress": {"phase": "stopped"}}

    ctx.emit("subtask_progress", phase="reason_explore")
    # 猎场也要能拿到打法:开局按操作员那句话先激活一轮(和对话轮同一套选择逻辑),
    # 之后由循环自己按信号/按需继续激活。以前这条路上一点知识都不进来。
    seed = skills.select_modules(str(job.payload.get("instruction") or job.payload.get("title") or ""),
                                 pack="pentest")
    summary = run_src_agent(
        bb_path, scope,
        max_cycles=int(job.payload.get("max_cycles") or 20),
        knowledge_seed=seed,
        max_explore_per_cycle=int(job.payload.get("max_explore") or 3),
        reasoner_prefer=reasoner, explorer_prefer=explorer,
        worker_id=f"console-{run_id}",
        request_budget=ctx.budget,
    )
    findings = 0
    if isinstance(summary, dict):
        findings = int(summary.get("findings") or summary.get("total_findings") or 0)
    ctx.emit("subtask_progress", phase="done", findings=findings,
             requests_used=(summary or {}).get("requests_used", 0),
             request_budget=(summary or {}).get("request_budget", 0))
    return {"summary_ref": str(bb_path), "progress": {"phase": "done", "findings": findings}}


DEFAULT_SURFACE_DELAY = 0.5
DELAY_ENV = "LODE_SURFACE_DELAY_SECONDS"
RATE_ENV = "LODE_REQUESTS_PER_SECOND"


def _scope_delay(job: JobRecord) -> float:
    """The one place a Console run's pacing is decided.

    The typed-target path read ``payload → env → 0.5`` while the confirmed-card
    path passed nothing and landed on the dataclass default (0.4) — two answers to
    the same question, 2 req/s vs 2.5 req/s, chosen by which entry point the
    operator happened to use.  ``0`` means "a very small number was given", not
    "nothing was given", so it must not be swallowed by ``or``.

    ``requests_per_second`` wins over ``delay_seconds`` when both are present, for
    the same reason it does in a scope file: the program states a rate, and turning
    it into an interval is our arithmetic to get wrong, not the operator's.

    The bounds come from ``agents.surface_discovery`` rather than being spelled again
    here.  They were two copies of ``0.1``/``30.0``, which is two answers waiting to
    drift.
    """
    from agents.surface_discovery import (
        MAX_DELAY_SECONDS, MIN_DELAY_SECONDS, _delay_from_rate,
    )

    rate = job.payload.get("requests_per_second")
    if rate is None or rate == "":
        rate = os.environ.get(RATE_ENV)
    if rate is not None and rate != "":
        from_rate = _delay_from_rate(rate)
        if from_rate is not None:
            return from_rate
    raw = job.payload.get("delay_seconds")
    if raw is None or raw == "":
        raw = os.environ.get(DELAY_ENV) or DEFAULT_SURFACE_DELAY
    try:
        return max(MIN_DELAY_SECONDS, min(float(raw), MAX_DELAY_SECONDS))
    except (TypeError, ValueError):
        return DEFAULT_SURFACE_DELAY


def _engagement(job: JobRecord, *, run_id: str) -> str:
    """Which budget this job draws on (see ``core.rate_limit.bucket_key``).

    Deliberately not the program name: the Console mints a fresh one per job
    (``console-<run_id>``) for display, and using it as the budget key gave every
    job its own bucket — 20 pasted targets became 20 independent budgets, so the
    program saw up to 20× the rate it declared.

    One conversation is one engagement.  Every job fanned out from a turn already
    carries that turn's ``turn_id`` (it is what makes "one stop stops them all"
    work), so the same field now also makes them share one budget.  A scope that
    does name a program wins — that is the operator's own identity for it.
    """
    declared = str(job.payload.get("program") or "").strip()
    if declared:
        return declared
    turn = str(getattr(job, "turn_id", "") or "").strip()
    return f"turn-{turn}" if turn else f"console-{run_id}"


def _typed_target_scope(job: JobRecord, *, run_id: str, target_url: str) -> Any:
    """Scope for a target the operator typed into the conversation.

    Only the host he actually typed is authorised.  This used to widen to the
    registrable domain (``www.a.com`` → ``a.com``), and ``allowed_domains``
    matches *descendants* — so pasting one URL opened the entire domain, including
    hosts the program explicitly excludes (measured on the NBA program: pasting
    ``www.nba.com`` made ``cms.``/``payment.``/``login-sandbox.nba.com`` /
    ``arcade.nba.com`` all requestable while every one of them is out of scope).
    Reaching further is now something the operator says explicitly, by naming the
    hosts — a run must never widen itself on the strength of a redirect or a
    suffix.

    **Read-only, explicitly.**  There is no authorisation document on this path, so
    there is nothing to derive a capability from — and deriving one from anything
    else (a toggle, the model, a default that happens to be permissive) would be
    inventing authorisation.  The two fields are passed rather than left to the
    dataclass default so that a future edit cannot widen this path by accident;
    ``tests/test_console_scope.py`` pins it.
    """
    from agents.surface_discovery import SurfaceScope
    from urllib.parse import urlparse

    parsed = urlparse(target_url)
    host = (parsed.hostname or "").lower()
    domains = [str(d).strip().lower() for d in (job.payload.get("allowed_domains") or []) if str(d).strip()]
    hosts = [str(h).strip().lower() for h in (job.payload.get("allowed_hosts") or []) if str(h).strip()]
    forbidden = [str(f).strip().lower() for f in (job.payload.get("forbidden_hosts") or []) if str(f).strip()]
    if host and host not in hosts:
        hosts.append(host)
    authorization = str(job.payload.get("authorization") or "")
    return SurfaceScope(
        program=f"console-{run_id}",
        authorization=authorization or f"Console operator authorized scan of {target_url}",
        engagement=_engagement(job, run_id=run_id),
        allowed_domains=tuple(domains), allowed_hosts=tuple(hosts),
        forbidden=tuple(forbidden), delay_seconds=_scope_delay(job),
        # 这条路没有授权文档,所以按构造只读 —— 显式写出来,不靠 dataclass 缺省。
        allowed_methods=("GET", "HEAD"), allow_request_body=False,
    )


def _handler_src_loop(job: JobRecord, ctx: JobContext) -> Dict[str, Any]:
    """Full SRC pipeline for a target typed into the conversation.

    A confirmed TargetCard must **not** take this path — see
    :func:`_scope_from_confirmed_card`.
    """
    run_id = str(ctx.job.payload.get("run_id") or job.job_id)
    scope = _typed_target_scope(job, run_id=run_id, target_url=job.target)
    return _run_scope(job, ctx, scope, run_id=run_id, target_url=job.target)


TARGET_RUN_KIND = "target_run"


def _scope_from_confirmed_card(card: Dict[str, Any], *, target_id: str, run_id: str,
                               engagement: str, delay: float) -> Any:
    """Build the run scope from a confirmed TargetCard — strictly.

    ``allowed_domains`` stays empty on purpose: a domain entry matches
    descendants, so widening a one-host card to its registrable domain would let
    the run reach hosts the operator never confirmed.  Non-wildcard
    ``allowed_hosts`` entries match exactly, which is what a card carries.

    ``engagement``/``delay`` are passed in rather than defaulted here: this is the
    path that used to inherit ``SurfaceScope``'s dataclass default while the typed
    path used the payload/env one, so the same operator got two different paces
    depending on how the run started.

    **Read-only, explicitly.**  A ``TargetCard``'s scope has exactly two keys
    (``allowed_hosts`` / ``forbidden_hosts`` — see ``core.intake_state``), so there is
    nowhere for a capability to be declared on this path even if the code wanted to
    read one.  Naming the fields makes that a decision instead of a coincidence, and
    ``tests/test_console_scope.py`` keeps it that way.  This is the path the
    authorisation-document chain was built to replace: a typed URL never did carry a
    method dimension, and ``_scope_from_engagement_document`` is where one arrives now.
    """
    from agents.surface_discovery import SurfaceScope

    data = card.get("scope") if isinstance(card.get("scope"), dict) else {}
    hosts = tuple(str(item).strip() for item in (data.get("allowed_hosts") or []) if str(item).strip())
    forbidden = tuple(str(item).strip() for item in (data.get("forbidden_hosts") or []) if str(item).strip())
    return SurfaceScope(
        program=f"console-{run_id}",
        authorization=f"confirmed_target_card:{target_id}",
        engagement=engagement,
        allowed_domains=(),
        allowed_hosts=hosts,
        forbidden=forbidden,
        delay_seconds=delay,
        allowed_methods=("GET", "HEAD"), allow_request_body=False,
    )


def _handler_target_run(job: JobRecord, ctx: JobContext) -> Dict[str, Any]:
    """Run one confirmed TargetCard.

    The card defines the scope, and its digest is re-checked here: the operator
    confirmed a specific object, so a card edited between confirmation and run
    has to fail rather than quietly authorise something else.
    """
    from console import intake as _intake

    target_id = str(job.payload.get("target_id") or "")
    run_id = str(job.payload.get("run_id") or job.job_id)
    stored = _intake.target_cards(None).load(
        target_id, expected_digest=str(job.payload.get("target_card_digest") or ""))
    if stored["target_card_ref"] != str(job.payload.get("target_card_ref") or ""):
        raise IntakeStateError("target_card_ref_mismatch")
    scope = _scope_from_confirmed_card(
        stored["target_card"], target_id=target_id, run_id=run_id,
        engagement=_engagement(job, run_id=run_id), delay=_scope_delay(job),
    )
    # Belt and braces: the card has to cover the URL we are about to fetch.
    allowed, reason = scope.check_url(job.target)
    if not allowed:
        raise IntakeStateError(f"target_not_in_confirmed_scope:{reason}")
    return _run_scope(job, ctx, scope, run_id=run_id, target_url=job.target)


ENGAGEMENT_HOST_RUN_KIND = "engagement_host_run"


def _is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _scope_from_engagement_document(document: Any, *, host: str, authorization_id: str,
                                    run_id: str, engagement: str) -> Any:
    """One host's slice of a confirmed authorisation document.

    每个 job 只拿到它自己那一台主机:文档授权的是"N 台主机各自可打",不是"N 台合起来
    构成一张更大的网"。把它折成一台是为了让 ``job.target`` 有意义 —— 一个覆盖整份
    清单的 scope 会让每台主机的运行都能碰到清单里的其他所有机器。

    主机之外的一切 —— 允许的方法、能不能带请求体、速率、排除清单、超时 —— 全部继承
    :meth:`SurfaceScope.from_mapping` 的结果,这里**绝不重新推导**。上面那个
    ``_scope_from_confirmed_card`` 就是反面教材:它只搬运 ``forbidden_hosts``,授权
    文档里的方法维度和 body 许可在那条路上直接没了。
    """
    from agents.surface_discovery import SurfaceScope

    base = SurfaceScope.from_mapping(document)
    scope = replace(
        base,
        program=f"console-{run_id}",
        authorization=f"engagement_authorization:{authorization_id}",
        engagement=engagement,
        allowed_domains=(),
        # IP 目标只按 allowed_ips 匹配(见 SurfaceScope.check_url),所以按主机是哪种
        # 地址放到对应的那一栏,而不是两栏都塞。
        allowed_hosts=() if _is_ip_host(host) else (host,),
        allowed_ips=(host,) if _is_ip_host(host) else (),
    )
    scope.require_authorization()
    return scope


def _handler_engagement_host_run(job: JobRecord, ctx: JobContext) -> Dict[str, Any]:
    """Run one host of a confirmed authorisation document.

    记录按 digest 复读,所以确认之后被动过的授权不会悄悄生效 —— 和 TargetCard 那条路
    同一个规矩,只是这次复读的是一整份文档。
    """
    from console.engagement import EngagementAuthorizationStore, EngagementStateError

    state_dir = Path(ctx.job.payload.get("_state_dir") or ".")
    run_id = str(ctx.job.payload.get("run_id") or job.job_id)
    authorization_id = str(ctx.job.payload.get("authorization_id") or "")
    host = str(ctx.job.payload.get("host") or "")
    resolved = EngagementAuthorizationStore(state_dir).load(
        authorization_id, expected_digest=str(ctx.job.payload.get("authorization_digest") or ""))
    record = resolved["authorization"]
    # 这一台必须真的在那份授权里 —— payload 是持久化记录,不能凭它就发请求。
    if host not in (record.get("hosts") or []):
        raise EngagementStateError("host_not_in_authorization")
    scope = _scope_from_engagement_document(
        record["document"], host=host, authorization_id=authorization_id, run_id=run_id,
        engagement=str(record.get("engagement") or record.get("program") or ""))
    allowed, reason = scope.check_url(job.target)
    if not allowed:
        raise EngagementStateError(f"target_not_in_confirmed_scope:{reason}")
    return _run_scope(job, ctx, scope, run_id=run_id, target_url=job.target,
                      authorization_id=authorization_id,
                      authorization_digest=resolved["authorization_digest"])


def start_target_run(
    state_dir: Path | str,
    *,
    confirmed: Dict[str, Any],
    session_id: str = "",
) -> Dict[str, Any]:
    """Start the run a consumed confirmation authorises.  Idempotent per intake.

    Only ever called with a receipt in hand, so the card this job re-reads and
    digest-checks is already the confirmed one.  A repeated call — double click, a
    replayed POST — returns the job that is already running instead of starting a
    second run of the same confirmation.
    """
    registry = get_registry(state_dir)
    intake_id = str(confirmed.get("intake_id") or "")
    existing = next(
        (record for record in registry.list(limit=0)
         if record.kind == TARGET_RUN_KIND
         and str(record.payload.get("intake_id") or "") == intake_id),
        None,
    )
    if existing is not None:
        return {"session_id": existing.session_id, "job_id": existing.job_id, "reused": True}

    session_id = session_id or f"src-{secrets.token_hex(6)}"
    instruction = str(confirmed.get("instruction") or "")
    job = registry.create(
        session_id=session_id, turn_id=f"T-{secrets.token_hex(4)}", kind=TARGET_RUN_KIND,
        target=str(confirmed.get("target") or ""),
        payload={
            "_state_dir": str(state_dir),
            "run_id": f"SL-{int(time.time())}-{secrets.token_hex(3)}",
            "via": "console_intake",
            "intake_id": intake_id,
            "options_digest": str(confirmed.get("options_digest") or ""),
            "target_id": str(confirmed.get("target_id") or ""),
            "target_card_ref": str(confirmed.get("target_card_ref") or ""),
            "target_card_digest": str(confirmed.get("target_card_digest") or ""),
            "instruction": instruction,
            # The conversation card shows the operator's own words, so the run is
            # identifiable without opening the job record.
            "title": instruction[:120],
        },
    )
    get_runner(state_dir).submit(job)
    return {"session_id": session_id, "job_id": job.job_id, "reused": False}


def start_engagement_run(state_dir: Path | str, *, confirmed: Dict[str, Any],
                         session_id: str = "") -> Dict[str, Any]:
    """Start one job per host of a consumed document confirmation.

    幂等键是 **(authorization_id, host)**,不是 intake:一次授权可能有 200 台主机,
    而它们不是一次提交 —— 中途崩了再确认一次,缺的那几台要能续上,已经起了的不能
    重复起。同一次授权的所有 job 共用一个 ``turn_id``,所以它们渲染在同一次对话里,
    "一次停止停掉全部"也照旧成立。

    主机顺序就是文档顺序,截断到文档自己写的 ``max_fanout``(缺省 30)。超出部分
    如实回报,不静默丢。
    """
    from console.engagement import EngagementStateError

    registry = get_registry(state_dir)
    record = confirmed.get("authorization") if isinstance(confirmed.get("authorization"), dict) else {}
    authorization_id = str(record.get("authorization_id") or "")
    authorization_digest = str(confirmed.get("authorization_digest") or "")
    hosts = [str(host) for host in (record.get("hosts") or []) if str(host)]
    if not authorization_id or not authorization_digest or not hosts:
        raise EngagementStateError("authorization_record_invalid")

    try:
        cap = max(1, int(record.get("max_fanout")))
    except (TypeError, ValueError):
        raise EngagementStateError("authorization_record_invalid") from None
    launched_hosts = hosts[:cap]
    skipped = len(hosts) - len(launched_hosts)

    existing = {
        str(item.payload.get("host") or ""): item
        for item in registry.list(limit=0)
        if item.kind == ENGAGEMENT_HOST_RUN_KIND
        and str(item.payload.get("authorization_id") or "") == authorization_id
    }
    # 已经起过的那几台决定了这次挂在哪个会话里 —— 续跑要接回原来那次对话,不是
    # 另开一个。
    session_id = session_id or (next(iter(existing.values())).session_id if existing else "")
    session_id = session_id or f"src-{secrets.token_hex(6)}"
    turn_id = existing and next(iter(existing.values())).turn_id or f"T-{secrets.token_hex(4)}"
    program = str(record.get("program") or "")
    engagement = str(record.get("engagement") or program)
    instruction = str(confirmed.get("instruction") or "")

    jobs: List[JobRecord] = []
    created = 0
    for host in launched_hosts:
        found = existing.get(host)
        if found is not None:
            jobs.append(found)
            continue
        job = registry.create(
            session_id=session_id, turn_id=turn_id, kind=ENGAGEMENT_HOST_RUN_KIND,
            target=f"https://{host}/",
            payload={
                "_state_dir": str(state_dir),
                "run_id": f"SL-{int(time.time())}-{secrets.token_hex(3)}",
                "via": "engagement",
                "intake_id": str(confirmed.get("intake_id") or ""),
                "authorization_id": authorization_id,
                "authorization_digest": authorization_digest,
                "host": host,
                "program": program,
                "engagement": engagement,
                "instruction": instruction,
                "title": instruction[:120] or host,
            },
        )
        jobs.append(job)
        created += 1
        get_runner(state_dir).submit(job)
    return {
        "session_id": session_id,
        "turn_id": turn_id,
        "authorization_id": authorization_id,
        "job_ids": [job.job_id for job in jobs],
        "launched": len(jobs),
        "created": created,
        "reused": created == 0,
        "hosts": launched_hosts,
        "skipped": skipped,
    }


def _handler_surface_scan(job: JobRecord, ctx: JobContext) -> Dict[str, Any]:
    """Surface discovery + autopilot only (no LLM loop).

    This is the cheap half of a hunt: 建面 before deciding what deserves the
    expensive reason/explore loop.  It used to build its own scope out of nothing
    (``allowed_domains=()``, ``allowed_hosts=()``), which ``require_authorization``
    rejects outright — so reaching it raised ``surface_scope_required`` every time.
    It now shares the typed-target scope, so it authorises exactly what the
    operator named and nothing else.
    """
    from agents.src_autopilot import SrcAutopilot

    state_dir = Path(ctx.job.payload.get("_state_dir") or ".")
    run_id = str(ctx.job.payload.get("run_id") or job.job_id)
    out_dir = state_dir / "src-agent-runs" / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    scope = _typed_target_scope(job, run_id=run_id, target_url=job.target)
    ctx.emit("subtask_progress", phase="autopilot")
    autopilot = SrcAutopilot(scope, out_dir / "autopilot-state.json", out_dir,
                             max_rounds=3, max_candidates=100,
                             blackboard_path=out_dir / "src-blackboard.json")
    autopilot.run_round([job.target])
    ctx.emit("subtask_progress", phase="done")
    return {"summary_ref": str(out_dir / "src-blackboard.json"), "progress": {"phase": "done"}}


# 一次粘贴最多起这么多任务。数字本身在 agents/scope_document 里 —— 授权文档也能写
# ``max_fanout``,两个来源必须是同一个常量,否则"上限是多少"就取决于走的哪个入口。
#
# 一个 job 一个桶那会儿这个数是安全阀;现在速率是硬盖(见 core/rate_limit),
# 它管的是队列有多长,不是程序会被打多快。清单里 200 个域名不等于 200 个猎场。


# 拒绝理由要翻成人话。只说"不行"而不说"为什么",操作员会以为产品坏了 —— 而这几条
# 恰恰是最容易被当成 bug 的地方(它们都是"你这份文档的写法我们不收")。
_SCOPE_REFUSAL_TEXT = {
    "scope_document_domains_not_allowed":
        "它用 allowed_domains 授权 —— 那是整片域,连带它的所有子域,而 Console 只收精确主机名",
    "scope_document_ip_range_not_allowed":
        "它用 CIDR 网段授权 —— 那是一片地址,同样不是精确主机名",
    "surface_authorization_required":
        "它没有写 authorization(书面授权说明)那一栏",
    "surface_scope_required":
        "它没有写任何主机、域或地址",
    "scope_document_no_hosts":
        "它列出的主机里,没有一台是能打的公网 http(s) 主机",
}


def _scope_document_refusal(exc: Any) -> str:
    reason = str(getattr(exc, "reason", "") or exc)
    detail = str(getattr(exc, "detail", "") or "")
    text = _SCOPE_REFUSAL_TEXT.get(reason, "它没通过授权文档的校验")
    extra = f"({detail})" if detail else ""
    return (f"这看起来是一份授权文档,但读不成一次可以开跑的授权:{text}{extra}。\n\n"
            f"什么都没起,也没有发出任何请求。改好之后把整份 JSON 重新贴一次就行 —— "
            f"前后不要带说明文字,否则它就只是聊天里的一段话了。")


def _scope_preview_notice(view: Dict[str, Any]) -> str:
    """The durable prose record of what the operator is about to authorise.

    账本里那一行已经逐项列出了细节,所以这里不重复整份清单 —— 复述一遍只会让人
    多读一遍,而两处说法一旦不一致,读的人不知道该信哪个。这里只留决策要看的那几件
    事(以及"现在还没发请求")。
    """
    summary = view.get("summary") if isinstance(view.get("summary"), dict) else {}
    hosts = [str(host) for host in (summary.get("hosts") or [])]
    rejected = summary.get("rejected") or []
    program = str(summary.get("program") or "").strip() or "未命名"
    rate = float(summary.get("requests_per_second") or 0.0)
    cap = int(summary.get("max_fanout") or 0)
    will_run = min(len(hosts), cap) if cap else len(hosts)

    lines = [
        "这是一份授权文档,不是一次狩猎请求 —— 确认之前不发起任何请求。",
        f"程序 {program},{len(hosts)} 台主机"
        + (f",{rate:g} req/s(这份授权下所有任务共用一个预算)" if rate else "") + "。",
    ]
    if len(hosts) > will_run:
        lines.append(f"将起 {will_run} 个任务;另有 {len(hosts) - will_run} 台超出文档自己写的"
                     f"上限 {cap},这次不起。")
    else:
        lines.append(f"将起 {will_run} 个任务 —— 每个任务只覆盖它自己那一台主机。")
    if rejected:
        lines.append(f"另有 {len(rejected)} 台被拦下(不是公网 http(s),或通配主机)。")
    lines.append("在待确认队列里点确认之后才开跑。")
    return "\n".join(lines)


def _pending_conflict_notice(state_dir: Path | str) -> str:
    """一个槽能放两种东西,所以挡路的是哪一种要说出来。"""
    from console import intake as intake_bridge

    try:
        scope_preview = intake_bridge.scope_pending_preview(state_dir)
        target_preview = intake_bridge.pending_preview(state_dir)
    except OSError:
        scope_preview = target_preview = None
    if scope_preview is not None:
        summary = scope_preview.summary if isinstance(scope_preview.summary, dict) else {}
        return (f"（待确认队列里已经有一份授权文档:{summary.get('program') or '未命名'},"
                f"{len(summary.get('hosts') or [])} 台主机。先放弃它,再说下一份。）")
    if target_preview is not None:
        return f"（待确认队列里已经有一个目标:{target_preview.target}。先放弃它,再说下一份。）"
    return "（待确认队列里已经有一份待确认的东西。先放弃它,再说下一份。）"


def _handle_scope_document(ctx: JobContext, *, state_dir: Path | str, text: str) -> Optional[Dict[str, Any]]:
    """Handle a turn that **is** an authorisation document; ``None`` if it is not one.

    认不出来就返回 ``None``,让这一轮照常走聊天 —— 认错的代价(把聊天里引用的例子
    当成一次授权)比认不出的代价大得多,所以判定只有一处、而且刻意保守。
    """
    from agents import scope_document
    from console import intake as intake_bridge

    if scope_document.looks_like_scope_document(text) is None:
        return None

    result: Optional[Dict[str, Any]] = None
    try:
        preview = intake_bridge.start_scope_preview(state_dir, source="paste", text=text)
    except scope_document.ScopeDocumentError as exc:
        notice = _scope_document_refusal(exc)
    except IntakeStateError as exc:
        reason = str(exc)
        notice = (_pending_conflict_notice(state_dir) if reason == "pending_intake_exists"
                  else f"（这份文档没有被接受:{reason}。什么都没起,也没有发出任何请求。）")
    except OSError:
        notice = "（这份文档读通了,但落盘失败。什么都没起。）"
    else:
        view = intake_bridge.scope_preview_view(preview)
        # 事件里不带全文:原文在 intake ledger 里,确认时按 digest 复读。把 200 台
        # 主机再抄一遍进事件流,只会让两份"真相"有机会互相打架。
        ctx.emit("scope_preview", **{key: value for key, value in view.items() if key != "document"})
        notice = _scope_preview_notice(view)
        result = {"summary_ref": f"scope-preview:{preview.intake_id}",
                  "progress": {"routed": "scope_document", "hosts": len(preview.summary.get("hosts") or [])}}
    ctx.emit("assistant_message", text=notice)
    return result if result is not None else {"summary_ref": "",
                                              "progress": {"routed": "scope_document_refused"}}


def _handler_chat_turn(job: JobRecord, ctx: JobContext) -> Dict[str, Any]:
    """One conversation turn: route the intent, run chat, escalate if asked.

    Emits the unified event stream (user_message / mode_changed /
    subtask_started / assistant_message) so the turn renders inline alongside any
    subtask it launches.
    """
    from agents import src_chat
    from agents.scope_document import DEFAULT_MAX_FANOUT
    from core import intent_router, modes, skills

    state_dir = Path(ctx.job.payload.get("_state_dir") or ".")
    session_id = job.session_id
    text = str(job.payload.get("text") or "")
    mode_name = str(job.payload.get("mode") or modes.DEFAULT_MODE)
    mode = modes.get_mode(mode_name)

    ctx.emit("user_message", text=text)
    # 一份授权文档不是一次狩猎请求,而且必须在 route **之前**拦下来:
    # ``targets.split_targets`` 会很乐意拿 JSON 里那些裸主机名去扩 fan-out,于是一份
    # 200 台主机的文档会变成 30 个 job 和三十张互不相干的卡。
    document_result = _handle_scope_document(ctx, state_dir=state_dir, text=text)
    if document_result is not None:
        return document_result

    # 确定性规则先跑,读不懂的说法才落到这一个便宜的分类调用。这个回调必须传 ——
    # 不传的话 ``route`` 就只剩规则,而"看看这个站能不能打"这类说法只有分类器读得懂
    # (以前这里就没传,兜底整段是死代码,所以没认出来的话永远是"只回话")。
    decision = intent_router.route(text, mode=mode, llm_complete=src_chat._default_llm_complete)

    if decision.mode and decision.mode != mode.name:
        mode = modes.get_mode(decision.mode)
        ctx.emit("mode_changed", mode=mode.name)

    notice = ""
    if decision.escalates and (decision.target or decision.targets):
        if decision.subtask_kind not in HANDLERS:
            # The router proposes a kind nothing can run — an existing kind whose
            # executor was pulled, or (more often) one the LLM classifier invented.
            # Launching it would only mint a job that fails ``no_handler:<kind>``,
            # so the turn says so in the conversation instead.
            notice = (f"（未启动后台任务:{decision.subtask_kind} 还没有执行器,"
                      f"本轮只在对话里分析。）")
        else:
            # One job per asset: a pasted list is a batch of assets, and each one
            # hunts on its own target — a single job covering the union would
            # widen every asset's scope to the whole paste. They all share the
            # turn's turn_id, so they render inside this turn and one stop stops
            # them all. ``decision.target`` is just the first seed (the Feishu
            # path and older callers only know that field).
            #
            # Building the job is the last place that can refuse: past it the
            # target is durable and will really be requested. The rule path
            # already gated its seeds (``targets.py``), but a target the LLM
            # classifier named never saw the gate — so re-check here rather than
            # trust the producer.
            seeds = [s for s in (decision.targets or [decision.target]) if s]
            launchable = [s for s in seeds if not public_target_reason(s)]
            skipped: List[str] = []
            if len(launchable) < len(seeds):
                skipped.append(f"{len(seeds) - len(launchable)} 个不是公网 http(s)")
            launched = launchable[:DEFAULT_MAX_FANOUT]
            if len(launchable) > len(launched):
                skipped.append(f"{len(launchable) - len(launched)} 个超出本轮 {DEFAULT_MAX_FANOUT} 个的上限")

            # Subtask node: a blackboard intent + a durable job (DAG/lease handled
            # there). The runner announces each one (subtask_started) — don't emit
            # a second copy here.
            registry, runner = get_registry(state_dir), get_runner(state_dir)
            for seed in launched:
                run_id = f"SA-{int(time.time())}-{secrets.token_hex(3)}"
                subtask = registry.create(
                    session_id=session_id, turn_id=job.turn_id, kind=decision.subtask_kind,
                    target=seed,
                    payload={"run_id": run_id, "_state_dir": str(state_dir), "via": "intent_router",
                             "reason": decision.reason, "title": mode.title},
                )
                runner.submit(subtask)
            if skipped:
                notice = (f"（这份清单识别到 {len(seeds)} 个目标,起了 {len(launched)} 个;"
                          + "、".join(skipped) + " 没起。）")

    if decision.hint == intent_router.HINT_MODE_BLOCKS_HUNT:
        # 认出了"目标 + 动作词",却因为当前模式不发起请求而开不了跑。静默只回话
        # 等于把操作员晾在那儿 —— 他不知道是产品不干活还是自己少说了一句。
        notice = (f"（当前是「{mode.title}」模式,这一轮不会发起任何请求。"
                  f"说一句「进入挖洞模式」、或者把上面的模式切到「挖洞」,"
                  f"同样这句话就直接开跑。）")

    # 只注入 dispatcher + 第一轮地板模块。深度不走这里 —— 模型用 read_knowledge
    # 在认出面相的时候按需拉(见 core/skills.select_modules 与 SKILL.md §2)。
    prompt = skills.compose_prompt(mode.skill, modules=skills.select_modules(text, pack=mode.skill))
    if mode.system_fragment:
        prompt = (prompt + "\n\n" + mode.system_fragment).strip()
    session = src_chat._get_or_create_session(session_id, state_dir=state_dir)
    # ``mode.tools`` is what the model may call inline *in this turn* -- a different
    # axis from ``HANDLERS`` above, which is which background executors exist. They
    # are deliberately independent: a kind can be declared in ``SUBTASK_FOR_MODE``
    # with no executor, and a mode can carry inline tools with no executor at all.
    reply = src_chat.chat(session, text, system_prompt=prompt or None,
                          tool_names=mode.tools, fallback_prompt=mode.system_fragment or None)
    ctx.emit("assistant_message", text=f"{notice}\n\n{reply}" if notice else reply)
    return {"summary_ref": f"session:{session_id}", "progress": {"mode": mode.name,
                                                                "routed": decision.action}}


HANDLERS = {"src_loop": _handler_src_loop, "surface_scan": _handler_surface_scan,
            "chat_turn": _handler_chat_turn, TARGET_RUN_KIND: _handler_target_run,
            ENGAGEMENT_HOST_RUN_KIND: _handler_engagement_host_run}


# -- report back into the conversation ---------------------------------------
# A run that ends silently is the worst outcome: the operator launched it from
# the conversation, so the conversation is where its answer belongs.  The runner
# already emits subtask_finished, but that is a machine event — this turns the
# run's own blackboard into one assistant message so the turn is actually closed.
#
# The blackboard holds findings as *hints* (see SrcAgentLoop._process_explorer_result):
# high confidence marks the intent blocked for human review, medium completes it.
#
# Every handler that leaves a blackboard behind, i.e. every one but ``chat_turn`` —
# that turn already emits its own assistant_message, and reporting on it would just
# echo the reply back.  Derived from HANDLERS so a new run kind cannot be forgotten.
RUN_KINDS = frozenset(HANDLERS) - {"chat_turn"}

REPORT_SYSTEM = """\
你是 SRC 挖洞的执行总结者。只根据给定材料说话:不要推测,不要补充材料里没有的漏洞。
中文,三句以内,直接给结论——发现了什么、置信度如何、下一步建议做什么。
材料里没有发现就直说没有发现。不要复述任务数量,不要客套话。"""

_REPORT_STATE: Dict[str, Any] = {"tried": False, "fn": None}


def _report_llm() -> Optional[Callable[[str, str], Optional[str]]]:
    """The completion seam for the report; ``None`` when no transport is available."""
    if _REPORT_STATE["tried"]:
        return _REPORT_STATE["fn"]
    _REPORT_STATE["tried"] = True
    try:
        from core.llm_client import complete_messages
    except Exception:  # noqa: BLE001 - a report is optional
        _REPORT_STATE["fn"] = None
        return None

    def _complete(system: str, user: str) -> Optional[str]:
        try:
            message = complete_messages(
                [{"role": "system", "content": system}, {"role": "user", "content": user}],
                timeout=60.0, max_tokens=800, temperature=0.2,
            )
        except Exception:  # noqa: BLE001 - a report must never fail a job
            return None
        if not message:
            return None
        return str(message.get("content") or "").strip() or None

    _REPORT_STATE["fn"] = _complete
    return _complete


def _blackboard_digest(doc: Dict[str, Any]) -> str:
    """Compact, factual digest of a finished run. Facts only, no interpretation."""
    workmem = doc.get("workmem") if isinstance(doc.get("workmem"), dict) else {}
    intents = [i for i in (doc.get("intents") or []) if isinstance(i, dict)]
    hints = [h for h in (doc.get("hints") or []) if isinstance(h, dict)]
    dead_ends = [d for d in (doc.get("dead_ends") or []) if isinstance(d, dict)]

    def count(status: str) -> int:
        return sum(1 for i in intents if str(i.get("status") or "") == status)

    lines: List[str] = []
    goal = str(workmem.get("goal") or "").strip()
    if goal:
        lines.append(f"目标:{goal}")
    lines.append(
        f"任务 {len(intents)} 个:完成 {count('completed')}、"
        f"待人工复核 {count('blocked')}、死路 {len(dead_ends)}"
    )
    if hints:
        lines.append("发现(explorer 给出,未经验证):")
        for h in hints[-12:]:
            lines.append(f"- {str(h.get('hint') or '')[:300]}")
    else:
        lines.append("发现:无")
    focus = str(workmem.get("focus") or "").strip()
    if focus:
        lines.append(f"最后的推理焦点:{focus[:300]}")
    return "\n".join(lines)


def _report_back(state_dir: Path | str, job: JobRecord) -> None:
    """Close the loop: turn a finished run's blackboard into one assistant message."""
    if job.kind not in RUN_KINDS or not job.summary_ref:
        return
    try:
        doc = json.loads(Path(job.summary_ref).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    if not isinstance(doc, dict):
        return
    complete = _report_llm()
    if complete is None:
        return
    text = complete(REPORT_SYSTEM, _blackboard_digest(doc))
    if not text:
        # No model, or it produced nothing: stay silent. A canned line would be
        # noise dressed up as analysis.
        return
    _emit(state_dir, job.session_id, "assistant_message", {"text": text, "job_id": job.job_id})


# -- notify (best effort) ----------------------------------------------------
def _notify_hook() -> Optional[Callable[..., Any]]:
    if _NOTIFY_STATE["tried"]:
        return _NOTIFY_STATE["fn"]
    _NOTIFY_STATE["tried"] = True
    try:
        from notify.broadcaster import Broadcaster  # type: ignore
        _NOTIFY_STATE["fn"] = Broadcaster(audit_path=None)
    except Exception:  # noqa: BLE001 - notification is optional
        _NOTIFY_STATE["fn"] = None
    return _NOTIFY_STATE["fn"]


def _on_terminal(job_id: str, status: str) -> None:
    """A job reached a terminal state: close the loop, then notify.

    The two steps are independent on purpose — the Feishu hook used to return
    early when no broadcaster could be imported, which would have swallowed the
    report for every installation without one.
    """
    state_dir = ""
    job: Optional[JobRecord] = None
    for key, entry in _ENTRIES.items():
        found = entry["registry"].get(job_id)
        if found is not None:
            state_dir, job = key, found
            break
    if job is None:
        return
    # Only a completed run has a blackboard worth summarising; a failed one is
    # already visible as a failed subtask row and its error text is internal.
    if status == "completed":
        _report_back(state_dir, job)
    _notify_terminal(job, status)


def _notify_terminal(job: JobRecord, status: str) -> None:
    """Feishu notification when a job finishes while the operator is away."""
    broadcaster = _notify_hook()
    if broadcaster is None:
        return
    elapsed = max(0.0, (job.finished_at or time.time()) - (job.started_at or job.created_at))
    label = {"completed": "finished", "failed": "failed", "interrupted": "interrupted"}.get(status, status)
    try:
        broadcaster.broadcast_task_terminal(
            job.target or job.job_id, task_id=job.job_id, status=label,
            elapsed=f"{int(elapsed)}s", report_ready=bool(job.summary_ref),
        )
    except Exception:  # noqa: BLE001
        pass


# -- singletons --------------------------------------------------------------
def _entry(state_dir: Path | str) -> Dict[str, Any]:
    key = str(Path(state_dir).resolve())
    with _LOCK:
        entry = _ENTRIES.get(key)
        if entry is None:
            registry = JobRegistry(Path(state_dir) / "jobs")
            runner = JobRunner(
                registry=registry, handlers=HANDLERS,
                on_event=lambda sid, kind, payload: _emit(state_dir, sid, kind, payload),
                notify_fn=_on_terminal,
            )
            entry = {"registry": registry, "runner": runner}
            _ENTRIES[key] = entry
        return entry


def _emit(state_dir: Path | str, session_id: str, kind: str, payload: Dict[str, Any]) -> None:
    if not session_id:
        return
    try:
        get_log(state_dir, session_id).append(kind, session_id=session_id, **payload)
    except Exception:  # noqa: BLE001 - event sink must never fail a job
        pass


def get_registry(state_dir: Path | str) -> JobRegistry:
    return _entry(state_dir)["registry"]


def get_runner(state_dir: Path | str) -> JobRunner:
    return _entry(state_dir)["runner"]


def active_jobs(state_dir: Path | str, *, session_id: str = "") -> list:
    return [r for r in get_registry(state_dir).list(limit=0, active_only=True)
            if not session_id or r.session_id == session_id]


def recover(state_dir: Path | str, *, auto_resume: bool = False) -> list:
    """Mark jobs whose owning process died. Called at app start-up."""
    return get_registry(state_dir).recover(auto_resume=auto_resume)


def shutdown_all(*, wait: bool = False) -> None:
    with _LOCK:
        entries = list(_ENTRIES.values())
    for entry in entries:
        try:
            entry["runner"].shutdown(wait=wait)
        except Exception:  # noqa: BLE001
            pass


__all__ = [
    "HANDLERS", "TARGET_RUN_KIND", "ENGAGEMENT_HOST_RUN_KIND", "active_jobs", "events_path",
    "get_log", "get_registry", "get_runner", "recover", "session_dir", "shutdown_all",
    "start_engagement_run", "start_target_run", "ACTIVE",
]
