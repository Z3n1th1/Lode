"""Small durable blackboard for bounded SRC surface work.

The blackboard borrows the useful coordination ideas from Cairn/Muteki while
keeping the execution boundary explicit: facts are observations, intents are
human/runner gated work items, and claims are short leases.  It never performs
network activity and it never stores raw request/response data.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from core.file_lock import AdvisoryFileLock, replace_with_retry


SCHEMA = "SrcBlackboard/v1"
EVENT_SCHEMA = "SrcBlackboardEvent/v1"
MAX_ITEMS = 2_000
MAX_EVENTS = 4_000
DEFAULT_LEASE_SECONDS = 15 * 60
MAX_LEASE_SECONDS = 2 * 60 * 60
# 失败重试:transient 失败按退避重排,超过上限才落到 dead_end(memfit 式 fail→retry)。
DEFAULT_MAX_ATTEMPTS = 3
# 依赖满足的终态:某 intent 的所有 depends_on 都进入下列状态后才可被 claim。
_DEP_SATISFIED = frozenset({"completed", "blocked", "dead_end"})
# 时间线:条目按固定分钟桶(绝对时间对齐)分组渲染,便于历史压缩 + prompt 前缀稳定。
TIMELINE_BUCKET_MINUTES = 3
MAX_TIMELINE_ITEMS = 2_000
_SECRET_TEXT = re.compile(r"(?i)\b(?:token|password|passwd|secret|authorization|cookie|api[-_]?key|signature|sig)\s*[:=]\s*(?:bearer\s+)?[^\s,;]+")


def _text(value: Any, limit: int = 300) -> str:
    return str(value or "").strip()[:limit]


def _safe_url(value: Any) -> str:
    raw = _text(value, 500)
    try:
        parsed = urlsplit(raw)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            return ""
        names = []
        for key, _value in parse_qsl(parsed.query, keep_blank_values=True):
            key = _text(key, 80)
            if key:
                names.append(f"{quote(key, safe='._-')}=[redacted]")
        return urlunsplit((parsed.scheme.lower(), parsed.netloc, parsed.path or "/", "&".join(dict.fromkeys(names)), ""))
    except ValueError:
        return ""


# 哪些查询参数是凭据:名字命中就整条丢掉。两个用法的分界线就在这里 —— 落盘和给模型
# 看的一律打码(``_safe_url``);真要发出去的那一份必须把凭据整条拿掉、其余保留原值
# (``probe_url``),因为"不回放捡来的凭据"是 ROE 的硬要求。
SENSITIVE_QUERY_KEY = re.compile(
    r"(?i)(?:token|auth|authorization|cookie|session|secret|password|passwd|api[-_]?key|signature|sig)"
)


def probe_url(value: Any) -> str:
    """The URL we may actually fetch: credential params dropped, the rest kept.

    ``_safe_url`` replaces *every* value with ``[redacted]`` — correct for what gets
    persisted and shown, and a guaranteed 404 when requested.  Those two jobs were
    conflated: the redacted form was the only form, and it was also what the Explorer
    was handed, so every candidate carrying a plain id was fetched as
    ``?token=[redacted]&id=[redacted]``.  This is the executable twin.

    A param whose *name* looks like a credential is removed whole rather than
    masked — masking would still send the name and an obviously bogus value, and
    replaying the real one is exactly what is not allowed.
    """
    raw = _text(value, 500)
    try:
        parsed = urlsplit(raw)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return ""
        if parsed.username or parsed.password:
            return ""
        kept = [
            (key, item) for key, item in parse_qsl(parsed.query, keep_blank_values=True)
            if _text(key, 80) and not SENSITIVE_QUERY_KEY.search(str(key))
        ]
        return urlunsplit((parsed.scheme.lower(), parsed.netloc, parsed.path or "/",
                           urlencode(kept, doseq=True) if kept else "", ""))
    except ValueError:
        return ""


def _safe_text(value: Any, limit: int) -> str:
    return _SECRET_TEXT.sub("[redacted]", _text(value, limit))


def _priority(value: Any) -> int:
    try:
        return max(0, min(100, int(float(value))))
    except (TypeError, ValueError, OverflowError):
        return 0


_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")
# URL 里的通用 token 对"相似"没有区分度,排除掉,否则所有 URL 都互相命中。
_GENERIC_TOKENS = frozenset({"https", "http", "www", "com", "net", "org", "html", "index", "json", "php"})


def _match_score(query: str, blob: str) -> int:
    """Cheap keyword/entity similarity: substring hit + shared word tokens.

    Deterministic on purpose — the retrieval layer must not need a model or a
    network call, and identical state must always rank identically.
    """
    if not query or not blob:
        return 0
    blob = blob.lower()
    score = 4 if query in blob else 0
    query_tokens = {token for token in _TOKEN_SPLIT.split(query) if len(token) >= 3}
    blob_tokens = {token for token in _TOKEN_SPLIT.split(blob) if len(token) >= 3}
    if query_tokens and blob_tokens:
        score += len((query_tokens & blob_tokens) - _GENERIC_TOKENS)
    return score


def _digest(*parts: Any) -> str:
    value = "\x1f".join(_text(part, 2_000) for part in parts)
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]


def _bounded_list(value: Any, limit: int = MAX_ITEMS, *, keep: str = "tail") -> List[Dict[str, Any]]:
    """Bound a list to the end that actually matters.

    ``tail`` (the default) is for append-only lists — facts, hints, events, the
    timeline. The newest are at the end and those are the ones to keep.

    ``head`` is for ``intents``, which are *stored* in descending priority order
    (see ``sync_candidates``). Taking the tail there kept the 2000 lowest-priority
    intents and threw away the best ones — the same inversion as the prompt
    builder's, one layer down.
    """
    if not isinstance(value, list):
        return []
    rows = [item for item in value if isinstance(item, dict)]
    return rows[:limit] if keep == "head" else rows[-limit:]


class SrcBlackboard:
    """Process-safe, atomic blackboard with single-worker intent leases."""

    def __init__(
        self,
        state_path: str | Path,
        *,
        now_fn: Optional[Callable[[], float]] = None,
        default_lease_seconds: int = DEFAULT_LEASE_SECONDS,
    ) -> None:
        self.state_path = Path(state_path)
        self.lock_path = self.state_path.with_name(self.state_path.name + ".lock")
        self._now = now_fn or time.time
        if not 1 <= int(default_lease_seconds) <= MAX_LEASE_SECONDS:
            raise ValueError("default_lease_seconds_out_of_range")
        self.default_lease_seconds = int(default_lease_seconds)

    def snapshot(self) -> Dict[str, Any]:
        """Return a bounded, validated snapshot without creating state files."""
        with AdvisoryFileLock(self.lock_path, create=False):
            return self._load_unlocked(create=False)

    def ensure(self) -> Dict[str, Any]:
        with AdvisoryFileLock(self.lock_path):
            state = self._load_unlocked(create=True)
            self._save_unlocked(state)
            return state

    def sync_candidates(self, candidates: Sequence[Mapping[str, Any]], *, run_id: str) -> Dict[str, int]:
        """Mirror safe candidate records into facts and queued intents."""
        now = self._now()
        with AdvisoryFileLock(self.lock_path):
            state = self._load_unlocked(create=True)
            facts = {str(item.get("fact_id")): item for item in state["facts"] if item.get("fact_id")}
            intents = {str(item.get("intent_id")): item for item in state["intents"] if item.get("intent_id")}
            added_facts = added_intents = 0
            # 本批观察 = 一个 episode(graphiti 概念):所有事实都带溯源到它。
            episode_id = "T-" + _digest("episode", run_id, now, len(state["timeline"]))
            for candidate in candidates[:MAX_ITEMS]:
                if not isinstance(candidate, Mapping):
                    continue
                cid = _text(candidate.get("candidate_id"), 80)
                url = _safe_url(candidate.get("url"))
                if not cid or not url:
                    continue
                # 执行用的那一份。展示用的 ``url`` 把每个参数值都打码了,拿它去请求
                # 必然 404 —— 而黑板同时是执行的唯一真相源,所以两份都要带。
                probe = probe_url(candidate.get("probe_url")) or url
                fact_id = "F-" + _digest("candidate", cid)
                fact = facts.get(fact_id)
                if fact is None:
                    fact = {
                        "fact_id": fact_id,
                        "kind": "src_candidate",
                        "candidate_id": cid,
                        "url": url,
                        "probe_url": probe,
                        "priority": _priority(candidate.get("priority")),
                        "sources": [_text(item, 40) for item in (candidate.get("sources") or [])[:12]],
                        "run_id": _text(run_id, 80),
                        "confidence": "observed",
                        # 时序事实(graphiti 式):失效不删除,保留有效期窗口。
                        "valid_from": now,
                        "valid_to": None,
                        "superseded_by": "",
                        "episode_id": episode_id,
                        "created_at": now,
                        "updated_at": now,
                    }
                    facts[fact_id] = fact
                    added_facts += 1
                else:
                    fact["updated_at"] = now
                    fact["run_id"] = _text(run_id, 80)
                intent_id = "I-" + _digest("src-review", cid)
                intent = intents.get(intent_id)
                if intent is None:
                    intent = {
                        "intent_id": intent_id,
                        "kind": "src_authorized_review",
                        "candidate_id": cid,
                        "target": url,
                        # 真正会被请求的那个 URL;``target`` 是给人看的去敏形式。
                        "probe_url": probe,
                        "priority": _priority(candidate.get("priority")),
                        "phase": _text(candidate.get("next_phase"), 64) or "A-passive-triage",
                        "status": "queued",
                        "requires_human_review": True,
                        "depends_on": [],
                        "attempts": 0,
                        "max_attempts": DEFAULT_MAX_ATTEMPTS,
                        "evidence_required": [
                            "scope_membership",
                            "authorized_request_result",
                            "business_impact_and_control_comparison",
                        ],
                        "created_at": now,
                        "updated_at": now,
                    }
                    intents[intent_id] = intent
                    added_intents += 1
                else:
                    intent["priority"] = max(_priority(intent.get("priority")), _priority(candidate.get("priority")))
                    intent["updated_at"] = now
            state["facts"] = list(facts.values())[-MAX_ITEMS:]
            state["intents"] = sorted(intents.values(), key=lambda item: (-int(item.get("priority") or 0), item["intent_id"]))[:MAX_ITEMS]
            state["timeline"].append({
                "item_id": episode_id,
                "at": now,
                "kind": "episode",
                "intent_id": "",
                "bucket": int(now // (TIMELINE_BUCKET_MINUTES * 60)),
                "summary": f"observe run={_text(run_id, 80)} facts+{added_facts} intents+{added_intents}",
            })
            state["timeline"] = state["timeline"][-MAX_TIMELINE_ITEMS:]
            self._event(state, "candidates_synced", {"run_id": _text(run_id, 80), "facts": added_facts, "intents": added_intents})
            self._save_unlocked(state)
            return {"facts_added": added_facts, "intents_added": added_intents}

    def add_hint(self, intent_id: str, hint: str, *, source: str = "operator") -> Dict[str, Any]:
        intent_id, hint, source = _text(intent_id, 80), _text(hint, 500), _text(source, 80)
        if not intent_id or not hint:
            raise ValueError("hint_required")
        with AdvisoryFileLock(self.lock_path):
            state = self._load_unlocked(create=True)
            hint = _safe_text(hint, 500)
            row = {"hint_id": "H-" + _digest(intent_id, hint), "intent_id": intent_id, "hint": hint, "source": source or "operator", "created_at": self._now()}
            if not any(item.get("hint_id") == row["hint_id"] for item in state["hints"]):
                state["hints"].append(row)
                state["hints"] = state["hints"][-MAX_ITEMS:]
                self._event(state, "hint_added", {"intent_id": intent_id, "source": row["source"]})
                self._save_unlocked(state)
            return row

    def add_dead_end(self, intent_id: str, reason: str, *, detail: str = "") -> Dict[str, Any]:
        intent_id, reason, detail = _text(intent_id, 80), _safe_text(reason, 120), _safe_text(detail, 500)
        if not intent_id or not reason:
            raise ValueError("dead_end_required")
        with AdvisoryFileLock(self.lock_path):
            state = self._load_unlocked(create=True)
            row = {"dead_end_id": "D-" + _digest(intent_id, reason), "intent_id": intent_id, "reason": reason, "detail": detail, "created_at": self._now()}
            if not any(item.get("dead_end_id") == row["dead_end_id"] for item in state["dead_ends"]):
                state["dead_ends"].append(row)
                state["dead_ends"] = state["dead_ends"][-MAX_ITEMS:]
                intent = self._intent(state, intent_id)
                if intent:
                    intent["status"] = "dead_end"
                    intent["updated_at"] = self._now()
                    # 死路 = 对应候选事实失效(保留历史窗口,不删除)。
                    cid = _text(intent.get("candidate_id"), 80)
                    if cid:
                        self._supersede_fact_unlocked(
                            state, "F-" + _digest("candidate", cid),
                            reason=reason, now=self._now(),
                        )
                self._event(state, "dead_end_recorded", {"intent_id": intent_id, "reason": reason})
                self._save_unlocked(state)
            return row

    def claim_next(
        self,
        worker_id: str,
        *,
        phases: Optional[Iterable[str]] = None,
        lease_seconds: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        worker_id = _text(worker_id, 120)
        if not worker_id:
            raise ValueError("worker_id_required")
        lease = self.default_lease_seconds if lease_seconds is None else int(lease_seconds)
        if not 1 <= lease <= MAX_LEASE_SECONDS:
            raise ValueError("lease_seconds_out_of_range")
        allowed = {str(item) for item in (phases or ()) if str(item)}
        now = self._now()
        with AdvisoryFileLock(self.lock_path):
            state = self._load_unlocked(create=True)
            self._reclaim_expired(state, now)
            row = next(
                (
                    item for item in state["intents"]
                    if item.get("status") == "queued"
                    and (not allowed or item.get("phase") in allowed)
                    and self._retry_ready(item, now)
                    and self._deps_satisfied(state, item)
                ),
                None,
            )
            if row is None:
                self._save_unlocked(state)
                return None
            claim = self._grant_claim(state, row, worker_id, lease, now)
            self._event(state, "intent_claimed", {"intent_id": row["intent_id"], "worker_id": worker_id})
            self._save_unlocked(state)
            return {"intent": dict(row), "claim": claim}

    def claim_intent(
        self,
        intent_id: str,
        worker_id: str,
        *,
        lease_seconds: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        """Claim one *specific* intent, honouring its DAG dependencies.

        ``claim_next`` hands back whatever is ready; the agent loop instead knows
        the intent it reasoned about and must not be given a different one (that
        would pair a hypothesis with the wrong target). Returns ``None`` when the
        intent is not queued, not retry-ready, or still has unmet ``depends_on``.
        """
        intent_id = _text(intent_id, 80)
        worker_id = _text(worker_id, 120)
        if not intent_id:
            raise ValueError("intent_id_required")
        if not worker_id:
            raise ValueError("worker_id_required")
        lease = self.default_lease_seconds if lease_seconds is None else int(lease_seconds)
        if not 1 <= lease <= MAX_LEASE_SECONDS:
            raise ValueError("lease_seconds_out_of_range")
        now = self._now()
        with AdvisoryFileLock(self.lock_path):
            state = self._load_unlocked(create=True)
            self._reclaim_expired(state, now)
            row = self._intent(state, intent_id)
            if (
                row is None
                or row.get("status") != "queued"
                or not self._retry_ready(row, now)
                or not self._deps_satisfied(state, row)
            ):
                return None
            claim = self._grant_claim(state, row, worker_id, lease, now)
            self._event(state, "intent_claimed", {"intent_id": row["intent_id"], "worker_id": worker_id})
            self._save_unlocked(state)
            return {"intent": dict(row), "claim": claim}

    @staticmethod
    def _grant_claim(
        state: Dict[str, Any], row: Dict[str, Any], worker_id: str, lease: int, now: float
    ) -> Dict[str, Any]:
        """Mark ``row`` claimed (replacing any prior claim) and return the lease."""
        row["status"] = "claimed"
        row["updated_at"] = now
        claim = {
            "claim_id": "C-" + _digest(row.get("intent_id"), worker_id, now, os.getpid()),
            "intent_id": row["intent_id"],
            "worker_id": worker_id,
            "claimed_at": now,
            "heartbeat_at": now,
            "lease_expires_at": now + lease,
        }
        state["claims"] = [item for item in state["claims"] if item.get("intent_id") != row["intent_id"]]
        state["claims"].append(claim)
        return claim

    def heartbeat(self, intent_id: str, worker_id: str, *, lease_seconds: Optional[int] = None) -> Dict[str, Any]:
        lease = self.default_lease_seconds if lease_seconds is None else int(lease_seconds)
        if not 1 <= lease <= MAX_LEASE_SECONDS:
            raise ValueError("lease_seconds_out_of_range")
        with AdvisoryFileLock(self.lock_path):
            state = self._load_unlocked(create=True)
            claim = self._owned_claim(state, intent_id, worker_id)
            if claim is None:
                raise ValueError("claim_not_owned")
            now = self._now()
            claim["heartbeat_at"] = now
            claim["lease_expires_at"] = now + lease
            self._save_unlocked(state)
            return dict(claim)

    def finish(self, intent_id: str, worker_id: str, *, status: str = "completed", result_ref: str = "") -> Dict[str, Any]:
        if status not in {"completed", "blocked", "dead_end"}:
            raise ValueError("invalid_intent_terminal_status")
        with AdvisoryFileLock(self.lock_path):
            state = self._load_unlocked(create=True)
            claim = self._owned_claim(state, intent_id, worker_id)
            if claim is None:
                raise ValueError("claim_not_owned")
            intent = self._intent(state, intent_id)
            if intent is None:
                raise ValueError("intent_not_found")
            intent["status"] = status
            intent["updated_at"] = self._now()
            if result_ref:
                intent["result_ref"] = _text(result_ref, 240)
            state["claims"] = [item for item in state["claims"] if item.get("intent_id") != intent_id]
            self._event(state, "intent_finished", {"intent_id": intent_id, "status": status})
            self._save_unlocked(state)
            return dict(intent)

    def fail(
        self,
        intent_id: str,
        worker_id: str,
        reason: str,
        *,
        detail: str = "",
        max_attempts: Optional[int] = None,
        backoff_seconds: float = 0.0,
    ) -> Dict[str, Any]:
        """Record a transient failure; requeue with backoff until the attempt cap.

        Inspired by memfit's fail→retry loop: a flaky fetch or an unavailable
        model should not permanently burn an intent. The intent is requeued
        (status ``queued``) with ``next_retry_at`` set until ``max_attempts`` is
        reached, at which point it becomes a terminal ``dead_end``.
        """
        intent_id = _text(intent_id, 80)
        reason = _safe_text(reason, 120)
        detail = _safe_text(detail, 500)
        if not intent_id or not reason:
            raise ValueError("fail_required")
        with AdvisoryFileLock(self.lock_path):
            state = self._load_unlocked(create=True)
            if self._owned_claim(state, intent_id, worker_id) is None:
                raise ValueError("claim_not_owned")
            intent = self._intent(state, intent_id)
            if intent is None:
                raise ValueError("intent_not_found")
            now = self._now()
            attempts = int(intent.get("attempts") or 0) + 1
            configured = intent.get("max_attempts")
            limit = max_attempts if max_attempts is not None else configured
            try:
                limit = max(1, int(limit))
            except (TypeError, ValueError):
                limit = DEFAULT_MAX_ATTEMPTS
            intent["attempts"] = attempts
            intent["last_error"] = reason
            intent["updated_at"] = now
            state["claims"] = [item for item in state["claims"] if item.get("intent_id") != intent_id]
            if attempts >= limit:
                intent["status"] = "dead_end"
                row = {
                    "dead_end_id": "D-" + _digest(intent_id, reason),
                    "intent_id": intent_id,
                    "reason": reason,
                    "detail": detail,
                    "created_at": now,
                }
                if not any(item.get("dead_end_id") == row["dead_end_id"] for item in state["dead_ends"]):
                    state["dead_ends"].append(row)
                    state["dead_ends"] = state["dead_ends"][-MAX_ITEMS:]
                self._event(state, "intent_failed_terminal", {"intent_id": intent_id, "attempts": attempts, "reason": reason})
            else:
                intent["status"] = "queued"
                try:
                    intent["next_retry_at"] = now + max(0.0, float(backoff_seconds))
                except (TypeError, ValueError):
                    intent["next_retry_at"] = now
                self._event(state, "intent_requeued", {"intent_id": intent_id, "attempts": attempts, "reason": reason})
            self._save_unlocked(state)
            return dict(intent)

    def set_dependencies(self, intent_id: str, depends_on: Iterable[str]) -> Dict[str, Any]:
        """Set the DAG edges for an intent; it cannot be claimed until they resolve."""
        intent_id = _text(intent_id, 80)
        if not intent_id:
            raise ValueError("intent_id_required")
        deps = sorted({_text(item, 80) for item in (depends_on or ()) if _text(item, 80)})
        with AdvisoryFileLock(self.lock_path):
            state = self._load_unlocked(create=True)
            intent = self._intent(state, intent_id)
            if intent is None:
                raise ValueError("intent_not_found")
            # 只保留可满足的边:指向不存在 intent 的边会让本节点永远不可 claim,
            # 会成环的边会让两边互相等待 —— 两者都直接丢弃,避免 DAG 死锁。
            dropped = 0
            clean: List[str] = []
            for dep in deps:
                if dep == intent_id or self._intent(state, dep) is None or self._creates_cycle(state, intent_id, dep):
                    dropped += 1
                else:
                    clean.append(dep)
            if sorted(intent.get("depends_on") or []) == clean:
                return dict(intent)  # 边没变就不写盘(agent 每轮都会调一次)
            intent["depends_on"] = clean
            intent["updated_at"] = self._now()
            self._event(state, "intent_dependencies_set", {"intent_id": intent_id, "count": len(clean), "dropped": dropped})
            self._save_unlocked(state)
            return dict(intent)

    @classmethod
    def _creates_cycle(cls, state: Dict[str, Any], intent_id: str, dep: str) -> bool:
        """True if ``dep`` already (transitively) depends on ``intent_id``."""
        by_id = {str(item.get("intent_id")): item for item in state["intents"]}
        seen: set[str] = set()
        stack = [dep]
        while stack:
            current = stack.pop()
            if current == intent_id:
                return True
            if current in seen:
                continue
            seen.add(current)
            node = by_id.get(current)
            if node:
                stack.extend(str(item) for item in (node.get("depends_on") or []))
        return False

    # ---------- 时间线(yaklang Timeline 的轻量版:追加 + 分桶 + 压缩头)----------

    def timeline_append(self, kind: str, *, intent_id: str = "", summary: str = "") -> Dict[str, Any]:
        """Append one observation to the append-only timeline."""
        kind = _safe_text(kind, 40)
        if not kind:
            raise ValueError("timeline_kind_required")
        with AdvisoryFileLock(self.lock_path):
            state = self._load_unlocked(create=True)
            now = self._now()
            item = {
                "item_id": "T-" + _digest(kind, intent_id, summary, now, len(state["timeline"])),
                "at": now,
                "kind": kind,
                "intent_id": _text(intent_id, 80),
                "summary": _safe_text(summary, 400),
                "bucket": int(now // (TIMELINE_BUCKET_MINUTES * 60)),
            }
            state["timeline"].append(item)
            state["timeline"] = state["timeline"][-MAX_TIMELINE_ITEMS:]
            self._event(state, "timeline_appended", {"kind": kind, "intent_id": item["intent_id"]})
            self._save_unlocked(state)
            return dict(item)

    def timeline_view(self, *, limit: int = 60, bucket_minutes: int = TIMELINE_BUCKET_MINUTES) -> Dict[str, Any]:
        """Recent items grouped into absolute-time buckets + the compressed head.

        Absolute-time bucketing gives a byte-stable prefix (same item always lands
        in the same bucket), which keeps LLM prompt caching effective.
        """
        with AdvisoryFileLock(self.lock_path, create=False):
            state = self._load_unlocked(create=False)
        window = max(1, int(limit))
        bucket_minutes = max(1, int(bucket_minutes))
        items = state["timeline"][-window:]
        groups: Dict[int, List[Dict[str, Any]]] = {}
        for item in items:
            key = int(item.get("at") or 0) // (bucket_minutes * 60)
            groups.setdefault(key, []).append(item)
        blocks = [
            {
                "bucket": key,
                "start": min(float(i.get("at") or 0) for i in rows),
                "count": len(rows),
                "items": rows,
            }
            for key, rows in sorted(groups.items())
        ]
        return {
            "head": dict(state.get("timeline_head") or {}),
            "blocks": blocks,
            "total": len(state["timeline"]),
        }

    def timeline_compress(self, *, keep: int = 40, max_chars: int = 1600) -> Dict[str, Any]:
        """Fold older timeline items into the compressed head (bounds prompt size)."""
        with AdvisoryFileLock(self.lock_path):
            state = self._load_unlocked(create=True)
            timeline = state["timeline"]
            if len(timeline) <= max(0, int(keep)):
                return dict(state.get("timeline_head") or {})
            older, newer = timeline[:-keep], timeline[-keep:]
            head = dict(state.get("timeline_head") or {"covered_end_at": 0.0, "version": 0, "text": ""})
            lines = [
                f"- [{i.get('kind')}] {i.get('summary') or i.get('intent_id') or ''}".strip()
                for i in older
            ]
            merged = ((str(head.get("text") or "") + "\n" + "\n".join(lines)).strip())[-max_chars:]
            head = {
                "covered_end_at": max(float(i.get("at") or 0) for i in older),
                "version": int(head.get("version") or 0) + 1,
                "text": merged,
            }
            state["timeline"] = newer
            state["timeline_head"] = head
            self._event(state, "timeline_compressed", {"folded": len(older), "version": head["version"]})
            self._save_unlocked(state)
            return dict(head)

    # ---------- 时序事实(graphiti 式:失效不删除,保留有效期)----------

    def supersede_fact(self, fact_id: str, *, by_fact_id: str = "", reason: str = "") -> Dict[str, Any]:
        """Invalidate a fact without deleting it (keeps its validity window)."""
        fact_id = _text(fact_id, 80)
        if not fact_id:
            raise ValueError("fact_id_required")
        with AdvisoryFileLock(self.lock_path):
            state = self._load_unlocked(create=True)
            row = self._supersede_fact_unlocked(
                state, fact_id, by_fact_id=by_fact_id, reason=reason, now=self._now(),
            )
            if row is None:
                raise ValueError("fact_not_found")
            self._event(state, "fact_superseded", {"fact_id": fact_id, "by": _text(by_fact_id, 80)})
            self._save_unlocked(state)
            return dict(row)

    def facts_as_of(self, ts: Optional[float] = None) -> List[Dict[str, Any]]:
        """Facts whose validity window covers ``ts`` (default: now)."""
        at = self._now() if ts is None else float(ts)
        with AdvisoryFileLock(self.lock_path, create=False):
            state = self._load_unlocked(create=False)
        return [fact for fact in state["facts"] if self._fact_valid_at(fact, at)]

    @staticmethod
    def _fact_valid_at(fact: Mapping[str, Any], at: float) -> bool:
        start_raw = fact.get("valid_from")
        if start_raw is None:
            start_raw = fact.get("created_at")
        try:
            start = float(start_raw or 0)
        except (TypeError, ValueError):
            start = 0.0
        end_raw = fact.get("valid_to")
        try:
            end = float(end_raw) if end_raw is not None else None
        except (TypeError, ValueError):
            end = None
        return start <= at and (end is None or end > at)

    def recall(
        self,
        queries: "str | Sequence[str]",
        *,
        limit: int = 5,
        per_query: int = 3,
    ) -> List[Dict[str, Any]]:
        """Retrieve similar past knowledge for each query (memory reuse).

        The keyword/entity stand-in for a vector store: for a new intent's target
        this surfaces earlier facts (valid *and* superseded), dead-ends and hints
        that point at the same host/path, so the agent reuses experience instead
        of rediscovering the same surface. Superseded facts keep their validity
        window from ``facts_as_of`` and come back with ``valid=False``.
        """
        if isinstance(queries, str):
            queries = [queries]
        normalized = [_text(item, 300).lower() for item in (queries or []) if _text(item, 300)]
        if not normalized:
            return []
        at = self._now()
        per_query = max(1, int(per_query))
        with AdvisoryFileLock(self.lock_path, create=False):
            state = self._load_unlocked(create=False)
        targets = {
            str(item.get("intent_id")): _text(item.get("target"), 300)
            for item in state["intents"] if item.get("intent_id")
        }
        results: List[Dict[str, Any]] = []
        for query in normalized[:max(1, int(limit))]:
            facts = []
            for fact in state["facts"]:
                if not isinstance(fact, dict):
                    continue
                score = _match_score(query, " ".join([
                    str(fact.get("candidate_id") or ""),
                    str(fact.get("url") or ""),
                    " ".join(str(item) for item in (fact.get("sources") or [])),
                ]))
                if score <= 0:
                    continue
                facts.append({
                    "fact_id": _text(fact.get("fact_id"), 80),
                    "url": _text(fact.get("url"), 300),
                    "candidate_id": _text(fact.get("candidate_id"), 80),
                    "priority": _priority(fact.get("priority")),
                    "run_id": _text(fact.get("run_id"), 80),
                    "valid": self._fact_valid_at(fact, at),
                    "superseded_reason": _text(fact.get("superseded_reason"), 120),
                    "score": score,
                })
            facts.sort(key=lambda row: (-row["score"], -row["priority"]))

            dead_ends = []
            for row in state["dead_ends"]:
                if not isinstance(row, dict):
                    continue
                target = targets.get(str(row.get("intent_id")), "")
                score = _match_score(query, f"{target} {row.get('reason') or ''} {row.get('detail') or ''}")
                if score <= 0:
                    continue
                dead_ends.append({
                    "intent_id": _text(row.get("intent_id"), 80),
                    "target": target,
                    "reason": _text(row.get("reason"), 120),
                    "created_at": row.get("created_at"),
                    "score": score,
                })
            dead_ends.sort(key=lambda row: -row["score"])

            hints = []
            for row in state["hints"]:
                if not isinstance(row, dict):
                    continue
                target = targets.get(str(row.get("intent_id")), "")
                score = _match_score(query, f"{target} {row.get('hint') or ''}")
                if score <= 0:
                    continue
                hints.append({
                    "intent_id": _text(row.get("intent_id"), 80),
                    "target": target,
                    "hint": _safe_text(row.get("hint"), 300),
                    "source": _text(row.get("source"), 64),
                    "score": score,
                })
            hints.sort(key=lambda row: -row["score"])

            results.append({
                "query": query,
                "facts": facts[:per_query],
                "dead_ends": dead_ends[:per_query],
                "hints": hints[:per_query],
            })
        return results

    @staticmethod
    def _supersede_fact_unlocked(
        state: Dict[str, Any],
        fact_id: str,
        *,
        by_fact_id: str = "",
        reason: str = "",
        now: Optional[float] = None,
    ) -> Optional[Dict[str, Any]]:
        fact = next((f for f in state["facts"] if f.get("fact_id") == fact_id), None)
        if fact is None:
            return None
        if fact.get("valid_to") is None:
            stamp = time.time() if now is None else now
            fact["valid_to"] = stamp
            fact["superseded_by"] = _text(by_fact_id, 80)
            if reason:
                fact["superseded_reason"] = _safe_text(reason, 120)
            fact["updated_at"] = stamp
        return fact

    # ---------- 工作记忆(yaklang TODO delta 的轻量版)----------

    def workmem_set(self, *, goal: Optional[str] = None, focus: Optional[str] = None) -> Dict[str, Any]:
        """Set the working-memory goal / focus (None = leave unchanged)."""
        with AdvisoryFileLock(self.lock_path):
            state = self._load_unlocked(create=True)
            workmem = state["workmem"]
            if goal is not None:
                workmem["goal"] = _safe_text(goal, 500)
            if focus is not None:
                workmem["focus"] = _safe_text(focus, 300)
            workmem["updated_at"] = self._now()
            self._event(state, "workmem_updated", {"goal": goal is not None, "focus": focus is not None})
            self._save_unlocked(state)
            return dict(workmem)

    def workmem_apply_todos(self, deltas: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
        """Apply incremental TODO deltas: add / update / done / blocked / drop."""
        if not isinstance(deltas, list):
            raise ValueError("todos_must_be_list")
        with AdvisoryFileLock(self.lock_path):
            state = self._load_unlocked(create=True)
            workmem = state["workmem"]
            todos = {
                str(t.get("todo_id")): t
                for t in (workmem.get("todos") or [])
                if isinstance(t, dict) and t.get("todo_id")
            }
            now = self._now()
            for delta in deltas[:50]:
                if not isinstance(delta, Mapping):
                    continue
                op = (_text(delta.get("op"), 16) or "add").lower()
                text = _safe_text(delta.get("text"), 300)
                todo_id = _text(delta.get("todo_id"), 60)
                if op == "add":
                    if not text:
                        continue
                    todo_id = todo_id or ("W-" + _digest(text, now, len(todos)))
                    todos[todo_id] = {"todo_id": todo_id, "text": text, "status": "open", "updated_at": now}
                    continue
                if not todo_id or todo_id not in todos:
                    continue
                if op == "update" and text:
                    todos[todo_id]["text"] = text
                elif op in ("done", "complete", "completed"):
                    todos[todo_id]["status"] = "done"
                elif op == "blocked":
                    todos[todo_id]["status"] = "blocked"
                elif op in ("drop", "remove", "delete"):
                    todos.pop(todo_id, None)
                    continue
                todos[todo_id]["updated_at"] = now
            workmem["todos"] = list(todos.values())[-200:]
            workmem["updated_at"] = now
            self._event(state, "workmem_todos_applied", {"count": len(deltas)})
            self._save_unlocked(state)
            return dict(workmem)

    @staticmethod
    def _retry_ready(intent: Mapping[str, Any], now: float) -> bool:
        try:
            return float(intent.get("next_retry_at") or 0) <= now
        except (TypeError, ValueError):
            return True

    @staticmethod
    def _deps_satisfied(state: Mapping[str, Any], intent: Mapping[str, Any]) -> bool:
        deps = intent.get("depends_on") or []
        if not deps:
            return True
        statuses = {str(item.get("intent_id")): item.get("status") for item in state["intents"]}
        return all(statuses.get(str(dep)) in _DEP_SATISFIED for dep in deps)

    def _load_unlocked(self, *, create: bool) -> Dict[str, Any]:
        if self.state_path.is_symlink():
            raise RuntimeError("src_blackboard_symlink_rejected")
        if not self.state_path.is_file():
            if not create:
                raise FileNotFoundError(self.state_path)
            return self._new_state()
        try:
            if self.state_path.stat().st_size > 8 * 1024 * 1024:
                raise RuntimeError("src_blackboard_state_too_large")
            value = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise RuntimeError("src_blackboard_state_unreadable") from exc
        if not isinstance(value, dict) or value.get("schema") != SCHEMA:
            raise RuntimeError("src_blackboard_state_schema_invalid")
        for key in ("facts", "intents", "dead_ends", "hints", "claims", "events"):
            if not isinstance(value.get(key), list):
                raise RuntimeError("src_blackboard_state_shape_invalid")
            value[key] = _bounded_list(
                value[key],
                MAX_EVENTS if key == "events" else MAX_ITEMS,
                keep="head" if key == "intents" else "tail",
            )
        # 向后兼容:老状态文件没有 timeline/workmem,补默认值(不报错,不丢数据)。
        if not isinstance(value.get("timeline"), list):
            value["timeline"] = []
        value["timeline"] = _bounded_list(value["timeline"], MAX_TIMELINE_ITEMS)
        if not isinstance(value.get("timeline_head"), dict):
            value["timeline_head"] = {"covered_end_at": 0.0, "version": 0, "text": ""}
        if not isinstance(value.get("workmem"), dict):
            value["workmem"] = {"goal": "", "focus": "", "todos": [], "updated_at": 0.0}
        if not isinstance(value["workmem"].get("todos"), list):
            value["workmem"]["todos"] = []
        return value

    def _save_unlocked(self, state: Dict[str, Any]) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        staged = self.state_path.with_name("." + self.state_path.name + ".next")
        staged.write_text(json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
        replace_with_retry(staged, self.state_path)

    def _new_state(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "revision": 0,
            "updated_at": self._now(),
            "facts": [],
            "intents": [],
            "dead_ends": [],
            "hints": [],
            "claims": [],
            "events": [],
            # 时间线:只追加的观察流水(工具调用/发现/死路/重试),旧条目可压缩进 head。
            "timeline": [],
            "timeline_head": {"covered_end_at": 0.0, "version": 0, "text": ""},
            # 工作记忆:当前目标/焦点 + TODO(增量 delta 更新),供 reasoner 直接读取。
            "workmem": {"goal": "", "focus": "", "todos": [], "updated_at": 0.0},
        }

    def _event(self, state: Dict[str, Any], kind: str, data: Mapping[str, Any]) -> None:
        state["revision"] = int(state.get("revision") or 0) + 1
        state["updated_at"] = self._now()
        state["events"].append({"schema": EVENT_SCHEMA, "revision": state["revision"], "ts": state["updated_at"], "kind": kind, **{str(k): _text(v, 160) if isinstance(v, str) else v for k, v in data.items()}})
        state["events"] = state["events"][-MAX_EVENTS:]

    @staticmethod
    def _intent(state: Dict[str, Any], intent_id: str) -> Optional[Dict[str, Any]]:
        return next((item for item in state["intents"] if item.get("intent_id") == intent_id), None)

    def _owned_claim(self, state: Dict[str, Any], intent_id: str, worker_id: str) -> Optional[Dict[str, Any]]:
        now = self._now()
        self._reclaim_expired(state, now)
        return next((item for item in state["claims"] if item.get("intent_id") == _text(intent_id, 80) and item.get("worker_id") == _text(worker_id, 120) and float(item.get("lease_expires_at") or 0) > now), None)

    @staticmethod
    def _reclaim_expired(state: Dict[str, Any], now: float) -> None:
        active = []
        expired_ids = set()
        for claim in state["claims"]:
            try:
                expired = float(claim.get("lease_expires_at") or 0) <= now
            except (TypeError, ValueError):
                expired = True
            if expired:
                expired_ids.add(claim.get("intent_id"))
            else:
                active.append(claim)
        state["claims"] = active
        for intent in state["intents"]:
            if intent.get("intent_id") in expired_ids and intent.get("status") == "claimed":
                intent["status"] = "queued"
                intent["updated_at"] = now


__all__ = ["SrcBlackboard", "SCHEMA"]
