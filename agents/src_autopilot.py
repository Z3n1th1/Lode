"""Bounded, restart-safe SRC surface triage.

This module turns one or more :mod:`surface_discovery` results into a durable
candidate queue.  It deliberately stops at candidate triage: no exploit,
credential reuse, lateral movement, form submission, or automatic finding claim
is performed here.  A later authorized runner may consume the queue only after
its own TargetCard and guardrails checks.

The workflow borrows the useful parts of the AgentOS proposal (rounds, A/B/C
staging, cross-round deduplication, and convergence) while rejecting its unsafe
"credential snowball" and unbounded attack-loop behavior.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_CORE_DIR = _PROJECT_ROOT / "core"
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))
if str(_CORE_DIR) not in sys.path:
    sys.path.insert(0, str(_CORE_DIR))

from core.file_lock import AdvisoryFileLock, replace_with_retry
from agents.surface_discovery import SurfaceResult, SurfaceScope, surface_to_dict
from core.src_blackboard import SENSITIVE_QUERY_KEY as _SENSITIVE_QUERY_KEY
from core.src_blackboard import VARIABLE_SEGMENT as _VARIABLE_SEGMENT
from core.src_blackboard import SrcBlackboard, probe_url as _probe_url


SCHEMA = "SrcAutopilotRun/v1"
SUMMARY_SCHEMA = "SrcAutopilotSummary/v1"
MAX_ROUNDS = 8
MAX_CANDIDATES = 500
MAX_NO_NEW_ROUNDS = 2
_HIGH_SIGNAL = {
    "admin", "auth", "oauth", "sso", "user", "users", "profile", "account",
    "order", "orders", "payment", "pay", "upload", "download", "export",
    "internal", "debug", "config", "graphql", "swagger", "openapi", "actuator",
}
_MEDIUM_SIGNAL = {
    "api", "apis", "v1", "v2", "v3", "service", "gateway", "query", "search",
    "list", "detail", "manage", "report", "schema", "metrics", "health", "status",
}
_SOURCE_WEIGHT = {
    "openapi": 30,
    "sourcemap": 25,
    "seed": 20,
    "js": 15,
    "html": 10,
    "robots": 8,
    "sitemap": 8,
}


def _safe_query(query: str) -> str:
    """Keep parameter names for triage, but never persist query values.

    This is the *display* form. It goes into the candidate queue, the markdown
    report and the reasoner's context — and it must never be requested, because
    ``[value]`` is not a value. See ``probe_url`` for the executable twin.
    """
    names: List[str] = []
    for key, _value in parse_qsl(query or "", keep_blank_values=True):
        key = str(key).strip()
        if not key:
            continue
        names.append(f"{key}=[redacted]" if _SENSITIVE_QUERY_KEY.search(key) else f"{key}=[value]")
    return "&".join(dict.fromkeys(names))


def _canonical_url(value: Any, scope: SurfaceScope, *, base_url: str = "") -> tuple[str, str, str] | None:
    """(display url, scope reason, executable url) — or ``None`` if out of scope.

    Two URLs, deliberately. ``display`` masks every query value, which is what may
    be persisted and shown; ``probe`` drops credential-bearing params whole and
    keeps the rest, which is what may be fetched. The Explorer used to be handed
    ``display``, so any candidate with a plain id was requested as
    ``?token=[redacted]&id=[redacted]`` and came back 404 every time.
    """
    raw = str(value or "").strip()
    if not raw:
        return None
    if raw.startswith(("/", "./", "../")):
        if not base_url:
            return None
        raw = urljoin(base_url.rstrip("/") + "/", raw)
    elif raw.startswith("//"):
        raw = "https:" + raw
    elif "://" not in raw:
        if not base_url:
            return None
        raw = urljoin(base_url.rstrip("/") + "/", raw)
    parsed = urlsplit(raw)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    scheme = parsed.scheme.lower()
    clean_path = parsed.path or "/"
    display = urlunsplit((scheme, parsed.netloc, clean_path, _safe_query(parsed.query), ""))
    allowed, reason = scope.check_url(display)
    if not allowed:
        return None
    probe = _probe_url(urlunsplit((scheme, parsed.netloc, clean_path, parsed.query, ""))) or display
    return display, reason, probe


def _score_candidate(url: str, sources: Iterable[str]) -> int:
    parts = urlsplit(url)
    segments = {item for item in re.split(r"[^a-z0-9]+", parts.path.lower()) if item}
    score = 10
    score += max((_SOURCE_WEIGHT.get(str(source).lower(), 5) for source in sources), default=0)
    score += 35 if segments & _HIGH_SIGNAL else 0
    score += 15 if segments & _MEDIUM_SIGNAL else 0
    score += 10 if parts.query else 0
    return min(100, score)


def _next_phase(score: int) -> str:
    if score >= 75:
        return "C-human-gated-verification"
    if score >= 45:
        return "B-authorized-review"
    return "A-passive-triage"


def _candidate_id(url: str) -> str:
    return "SC-" + hashlib.sha256(url.encode("utf-8")).hexdigest()[:12]


# 一个模板能记多少个具体实例。到顶就是"这个形状至少枚举了这么多",不假装精确 ——
# 枚举面 200 个 id 和 2000 个 id 对"这是个可枚举的对象引用"这个判断没有区别。
MAX_VARIANT_SAMPLES = 25


def _template_id(url: str) -> str:
    """The *shape* of an endpoint — one id per family, not per instance.

    ``/users/2`` and ``/users/37`` are one endpoint with a variable, not two
    candidates. Without this, one enumerable resource produces one candidate per id:
    200 candidates eat the whole ``max_candidates`` budget and the reasoner's whole
    50-intent window, so the interesting endpoints never reach the model.

    Host is deliberately *not* folded in — the merge key is ``(template_id, host)``,
    so the same shape on two hosts stays two candidates.

    Query values need no folding: the display form already collapses every value to
    ``[redacted]``/``[value]``, so ``?id=1`` and ``?id=2`` were always one candidate.
    """
    parsed = urlsplit(url)
    segments: List[str] = []
    for segment in (parsed.path or "/").split("/"):
        for marker, pattern in _VARIABLE_SEGMENT:
            if pattern.match(segment):
                segment = marker
                break
        segments.append(segment)
    template = "/".join(segments) + (f"?{parsed.query}" if parsed.query else "")
    return "ST-" + hashlib.sha256(template.encode("utf-8")).hexdigest()[:12]


def _host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


@dataclass
class CandidateRecord:
    url: str
    score: int
    # 真正去取的那个 URL(凭据参数已整条丢掉)。``url`` 只用于展示和落盘。
    probe_url: str = ""
    # 同一个形状的家族身份;``url`` 是这个家族里第一个见到的具体实例。
    template_id: str = ""
    # 这个模板见过哪些具体实例 —— ``variants`` 由它推出来,到 MAX_VARIANT_SAMPLES 封顶。
    variant_urls: List[str] = field(default_factory=list)
    sources: set[str] = field(default_factory=set)
    first_seen_round: int = 0
    last_seen_round: int = 0
    status: str = "queued"

    @property
    def candidate_id(self) -> str:
        # 仍然 hash **具体** url:改它会让已有黑板每个候选多出一对 fact/intent,而
        # sync_candidates 从不迁移 —— 那等于毁掉重启安全。
        return _candidate_id(self.url)

    @property
    def variants(self) -> int:
        return max(1, len(self.variant_urls))

    def as_dict(self) -> Dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "url": self.url,
            "probe_url": self.probe_url,
            "template_id": self.template_id,
            "variants": self.variants,
            "variant_samples": list(self.variant_urls),
            "path": urlsplit(self.url).path or "/",
            "priority": self.score,
            "sources": sorted(self.sources),
            "first_seen_round": self.first_seen_round,
            "last_seen_round": self.last_seen_round,
            "status": self.status,
            "next_phase": _next_phase(self.score),
            "requires_human_review": True,
            "evidence_required": [
                "scope_membership",
                "authorized_request_result",
                "business_impact_and_control_comparison",
            ],
        }


class SrcAutopilot:
    """Persisted candidate triage coordinator with explicit bounded rounds."""

    def __init__(
        self,
        scope: SurfaceScope,
        state_path: str | Path,
        out_dir: str | Path,
        *,
        max_rounds: int = 3,
        max_candidates: int = 100,
        max_no_new_rounds: int = MAX_NO_NEW_ROUNDS,
        max_scripts: int = 40,
        blackboard_path: Optional[str | Path] = None,
        discover_fn: Optional[Callable[..., SurfaceResult]] = None,
        now_fn: Optional[Callable[[], float]] = None,
        request_budget: Any = None,
    ) -> None:
        scope.require_authorization()
        if not 1 <= int(max_rounds) <= MAX_ROUNDS:
            raise ValueError(f"max_rounds must be between 1 and {MAX_ROUNDS}")
        if not 1 <= int(max_candidates) <= MAX_CANDIDATES:
            raise ValueError(f"max_candidates must be between 1 and {MAX_CANDIDATES}")
        if not 1 <= int(max_no_new_rounds):
            raise ValueError("max_no_new_rounds must be positive")
        if not 1 <= int(max_scripts) <= 100:
            raise ValueError("max_scripts must be between 1 and 100")
        self.scope = scope
        self.state_path = Path(state_path)
        self.out_dir = Path(out_dir)
        self.max_rounds = int(max_rounds)
        self.max_candidates = int(max_candidates)
        # A one-shot run (max_rounds=1) should remain valid with the normal
        # convergence default of two rounds; the hard round cap still wins.
        self.max_no_new_rounds = min(int(max_no_new_rounds), int(max_rounds))
        self.max_scripts = int(max_scripts)
        self.discover_fn = discover_fn
        # 爬虫的请求同样记在这一轮的额度上(见 core.rate_limit.RequestBudget)。
        self.request_budget = request_budget
        self._now = now_fn or time.time
        self._lock_path = self.state_path.with_name(self.state_path.name + ".lock")
        blackboard_file = Path(blackboard_path or self.state_path.with_name("src-blackboard.json"))
        if blackboard_file.resolve() == self.state_path.resolve() or blackboard_file.with_name(blackboard_file.name + ".lock").resolve() == self._lock_path.resolve():
            raise ValueError("blackboard_state_path_conflicts_with_autopilot_state")
        self.blackboard = SrcBlackboard(blackboard_file, now_fn=self._now)

    def run_round(
        self,
        targets: Optional[Sequence[str]] = None,
        *,
        results: Optional[Sequence[Mapping[str, Any] | SurfaceResult]] = None,
    ) -> Dict[str, Any]:
        """Run one bounded round.

        The first round may perform the existing passive surface discovery for
        explicitly supplied targets. Later rounds accept only new result
        documents, which makes a long-running external runner restart-safe and
        prevents this coordinator from silently expanding network scope.
        """
        self.scope.require_authorization()
        incoming = list(results or ())
        # Keep the complete state transition under one lease. This prevents two
        # scheduler processes from both observing the same round and overwriting
        # each other's candidates during a restart.
        with AdvisoryFileLock(self._lock_path):
            state = self._load_state_unlocked()
            if state is None:
                state = self._new_state()

            target_values = [str(item).strip() for item in (targets or ()) if str(item).strip()]
            if target_values:
                for target in target_values:
                    self._validate_target(target)
                state["targets"] = sorted(set(state.get("targets", [])) | set(target_values))
            if not state.get("targets") and incoming:
                state["targets"] = self._targets_from_results(incoming)
            if not state.get("targets"):
                raise ValueError("authorized_target_required")

            if state.get("status") in {"stopped", "completed"}:
                return self._summary(state, "already_terminal")
            if int(state.get("current_round", 0)) >= self.max_rounds:
                state["status"] = "stopped"
                state["stop_reason"] = "max_rounds"
                self._save_state_unlocked(state)
                self._write_outputs(state)
                return self._summary(state, "max_rounds")

            if not incoming and int(state.get("current_round", 0)) == 0:
                incoming = self._discover_initial(state["targets"])
            elif not incoming:
                state["status"] = "awaiting_input"
                state["stop_reason"] = "awaiting_next_surface_result"
                self._save_state_unlocked(state)
                self._write_outputs(state)
                return self._summary(state, "awaiting_next_surface_result")

            round_number = int(state.get("current_round", 0)) + 1
            new_count, blocked_count = self._merge_results(state, incoming, round_number)
            state["current_round"] = round_number
            state["updated_at"] = self._now()
            state["rounds"].append({
                "round": round_number,
                "new_candidates": new_count,
                "blocked_candidates": blocked_count,
                "input_results": len(incoming),
            })
            state["no_new_rounds"] = 0 if new_count else int(state.get("no_new_rounds", 0)) + 1
            if round_number >= self.max_rounds:
                state["status"] = "stopped"
                state["stop_reason"] = "max_rounds"
            elif int(state["no_new_rounds"]) >= self.max_no_new_rounds:
                state["status"] = "stopped"
                state["stop_reason"] = "converged_no_new_candidates"
            else:
                state["status"] = "awaiting_next_round"
                state["stop_reason"] = "awaiting_next_surface_result"
            self.blackboard.sync_candidates(state.get("candidates", []), run_id=str(state["run_id"]))
            self._save_state_unlocked(state)
            self._write_outputs(state)
            return self._summary(state, "round_completed")

    def _new_state(self) -> Dict[str, Any]:
        now = self._now()
        return {
            "schema": SCHEMA,
            "run_id": "SA-" + hashlib.sha256(f"{now}:{os.getpid()}".encode()).hexdigest()[:12],
            "status": "running",
            "stop_reason": "",
            "current_round": 0,
            "max_rounds": self.max_rounds,
            "max_candidates": self.max_candidates,
            "max_no_new_rounds": self.max_no_new_rounds,
            "no_new_rounds": 0,
            "targets": [],
            "candidates": [],
            "rounds": [],
            "created_at": now,
            "updated_at": now,
        }

    def _load_state(self) -> Optional[Dict[str, Any]]:
        with AdvisoryFileLock(self._lock_path):
            return self._load_state_unlocked()

    def _load_state_unlocked(self) -> Optional[Dict[str, Any]]:
        if self.state_path.is_symlink():
            raise RuntimeError("src_autopilot_state_symlink_rejected")
        if not self.state_path.is_file():
            return None
        try:
            if self.state_path.stat().st_size > 8 * 1024 * 1024:
                raise RuntimeError("src_autopilot_state_too_large")
            state = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise RuntimeError("src_autopilot_state_unreadable") from exc
        if not isinstance(state, dict) or state.get("schema") != SCHEMA:
            raise RuntimeError("src_autopilot_state_schema_invalid")
        if not isinstance(state.get("candidates"), list) or not isinstance(state.get("rounds"), list):
            raise RuntimeError("src_autopilot_state_shape_invalid")
        return state

    def _save_state(self, state: Dict[str, Any]) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        with AdvisoryFileLock(self._lock_path):
            self._save_state_unlocked(state)

    def _save_state_unlocked(self, state: Dict[str, Any]) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        staged = self.state_path.with_name("." + self.state_path.name + ".next")
        if staged.is_symlink():
            raise RuntimeError("src_autopilot_staging_symlink_rejected")
        staged.write_text(json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
        replace_with_retry(staged, self.state_path)

    def _validate_target(self, target: str) -> None:
        allowed, reason = self.scope.check_url(target)
        if not allowed:
            raise ValueError("target_rejected:" + reason)

    def _targets_from_results(self, results: Sequence[Mapping[str, Any] | SurfaceResult]) -> List[str]:
        targets: List[str] = []
        for item in results:
            payload = surface_to_dict(item) if isinstance(item, SurfaceResult) else item
            if not isinstance(payload, Mapping) or payload.get("schema") != "SrcSurfaceResult/v1":
                continue
            candidate = str(payload.get("target") or payload.get("base_url") or "").strip()
            if candidate:
                self._validate_target(candidate)
                targets.append(candidate)
        return sorted(set(targets))

    def _discover_initial(self, targets: Sequence[str]) -> List[Mapping[str, Any]]:
        from agents.surface_discovery import discover_surface

        discover = self.discover_fn or discover_surface
        payloads: List[Mapping[str, Any]] = []
        for target in targets:
            result = discover(self.scope, target, max_scripts=self.max_scripts,
                              budget=self.request_budget)
            self._audit_crawl(result)
            payload = surface_to_dict(result) if isinstance(result, SurfaceResult) else result
            if not isinstance(payload, Mapping):
                raise RuntimeError("src_autopilot_discovery_result_invalid")
            payloads.append(payload)
        return payloads

    def _audit_crawl(self, result: Any) -> None:
        """爬虫发出去的请求也要留痕。

        在 ``auto`` 这条路上 ``cmd_scan`` 会写 ``surface-*.json``,``auto`` 不写 —— 于是
        爬虫花掉的那部分额度(实测一轮 60 里占 21 个)在任何文件里都找不到。红线 10 要的是
        "测试全程留痕",所以它和 agent 走同一份 ``http-actions.jsonl``(在 run 目录里)。

        记的是"发过什么",不是响应内容:响应仍只留指纹或不留。
        """
        if isinstance(result, Mapping):
            payload: Mapping[str, Any] = result
        elif isinstance(result, SurfaceResult):
            payload = surface_to_dict(result)
        else:
            return
        blackboard_path = getattr(self.blackboard, "state_path", None)
        if blackboard_path is None:
            return
        try:
            from agents.src_agent import record_http_action
        except Exception:  # noqa: BLE001 - 审计失败不该让爬虫结果丢掉
            return
        label = f"surface discovery ({payload.get('target') or ''})"
        for row in payload.get("requests") or ():
            if not isinstance(row, Mapping):
                continue
            record_http_action(
                blackboard_path, url=str(row.get("url") or ""),
                result={"status": row.get("status"), "headers": {}, "body": "",
                        "method": "GET", "error": ""},
                reason=label, kind="crawl")
        for entry in payload.get("errors") or ():
            text = str(entry)
            if not text.startswith("blocked:"):
                continue
            # ``blocked:<url>:<reason>`` —— rpartition 取最后一个冒号,所以带端口的 URL
            # 和带冒号的 reason 都不会切错。
            url, _, reason = text[len("blocked:"):].rpartition(":")
            record_http_action(
                blackboard_path, url=url or text,
                result={"status": 0, "headers": {}, "body": "", "method": "GET",
                        "error": reason or "blocked"},
                reason=label, kind="crawl")

    def _merge_results(
        self,
        state: Dict[str, Any],
        results: Sequence[Mapping[str, Any] | SurfaceResult],
        round_number: int,
    ) -> tuple[int, int]:
        records: Dict[tuple, CandidateRecord] = {}
        for raw in state.get("candidates", []):
            if not isinstance(raw, Mapping) or not raw.get("url"):
                continue
            url = str(raw["url"])
            template_id = str(raw.get("template_id") or "") or _template_id(url)
            record = CandidateRecord(
                url=url,
                score=int(raw.get("priority", 0)),
                probe_url=str(raw.get("probe_url") or ""),
                template_id=template_id,
                sources={str(item) for item in (raw.get("sources") or ())},
                first_seen_round=int(raw.get("first_seen_round", 0)),
                last_seen_round=int(raw.get("last_seen_round", 0)),
                status=str(raw.get("status", "queued")),
            )
            samples = raw.get("variant_samples")
            if isinstance(samples, list):
                record.variant_urls = [str(item) for item in samples[:MAX_VARIANT_SAMPLES]] or [url]
            records[(template_id, _host_of(url))] = record
        new_count = 0
        blocked_count = 0
        for item in results:
            payload = surface_to_dict(item) if isinstance(item, SurfaceResult) else item
            if not isinstance(payload, Mapping) or payload.get("schema") != "SrcSurfaceResult/v1":
                blocked_count += 1
                continue
            base = str(payload.get("base_url") or payload.get("target") or "").strip()
            try:
                self._validate_target(base)
            except ValueError:
                blocked_count += 1
                continue
            values: List[tuple[Any, str]] = []
            for value in payload.get("paths") or ():
                values.append((value, "surface"))
            for value in payload.get("api_urls") or ():
                values.append((value, "api"))
            source_map = payload.get("sources") if isinstance(payload.get("sources"), Mapping) else {}
            for value, fallback_source in values:
                raw_sources = source_map.get(value) if isinstance(source_map, Mapping) else None
                sources = {str(item).lower() for item in (raw_sources or (fallback_source,)) if str(item).strip()}
                canonical = _canonical_url(value, self.scope, base_url=base)
                if canonical is None:
                    blocked_count += 1
                    continue
                clean_url, _reason, live_url = canonical
                template_id = _template_id(clean_url)
                key = (template_id, _host_of(clean_url))
                record = records.get(key)
                if record is not None:
                    record.sources.update(sources)
                    record.score = max(record.score, _score_candidate(clean_url, record.sources))
                    record.last_seen_round = round_number
                    if not record.probe_url:
                        record.probe_url = live_url
                    if (clean_url not in record.variant_urls
                            and len(record.variant_urls) < MAX_VARIANT_SAMPLES):
                        record.variant_urls.append(clean_url)
                    continue
                new_count += 1
                records[key] = CandidateRecord(
                    url=clean_url,
                    score=_score_candidate(clean_url, sources),
                    probe_url=live_url,
                    template_id=template_id,
                    variant_urls=[clean_url],
                    sources=sources,
                    first_seen_round=round_number,
                    last_seen_round=round_number,
                )
        ordered = sorted(records.values(),
                         key=lambda item: (-item.score, item.template_id, item.url))[: self.max_candidates]
        state["candidates"] = [item.as_dict() for item in ordered]
        return new_count, blocked_count

    def _write_outputs(self, state: Dict[str, Any]) -> None:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self._atomic_write(self.out_dir / "src-autopilot-state.json", json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True))
        candidates = {
            "schema": "SrcAutopilotCandidateQueue/v1",
            "run_id": state["run_id"],
            "status": state["status"],
            "candidates": state.get("candidates", []),
        }
        self._atomic_write(self.out_dir / "src-autopilot-candidates.json", json.dumps(candidates, ensure_ascii=False, indent=2, sort_keys=True))
        lines = [
            "# SRC Autopilot Candidate Queue",
            "",
            f"- run: `{state['run_id']}`",
            f"- status: `{state['status']}`",
            f"- round: `{state['current_round']}/{state['max_rounds']}`",
            f"- stop_reason: `{state.get('stop_reason') or '-'}`",
            "",
            "候选仅用于 scope 内的被动分诊；下一阶段必须由人工或已授权 runner 执行。",
            "",
            "## Candidates",
            "",
        ]
        for candidate in state.get("candidates", []):
            variants = int(candidate.get("variants") or 1)
            shape = f" variants={variants}" if variants > 1 else ""
            lines.append(
                f"- `{candidate['candidate_id']}` priority={candidate['priority']} "
                f"phase={candidate['next_phase']} url=`{candidate['url']}`{shape} "
                f"sources={','.join(candidate['sources']) or '-'}"
            )
        self._atomic_write(self.out_dir / "src-autopilot-candidates.md", "\n".join(lines) + "\n")

    @staticmethod
    def _atomic_write(path: Path, text: str) -> None:
        staged = path.with_name("." + path.name + ".next")
        if path.is_symlink() or staged.is_symlink():
            raise RuntimeError("src_autopilot_output_symlink_rejected")
        staged.write_text(text, encoding="utf-8")
        replace_with_retry(staged, path)

    @staticmethod
    def _summary(state: Dict[str, Any], event: str) -> Dict[str, Any]:
        candidates = state.get("candidates") or []
        return {
            "schema": SUMMARY_SCHEMA,
            "event": event,
            "run_id": state.get("run_id", ""),
            "status": state.get("status", ""),
            "stop_reason": state.get("stop_reason", ""),
            "round": int(state.get("current_round", 0)),
            "max_rounds": int(state.get("max_rounds", 0)),
            "candidate_count": len(candidates),
            "top_candidates": [
                {
                    "candidate_id": item.get("candidate_id"),
                    "priority": item.get("priority"),
                    "next_phase": item.get("next_phase"),
                    "url": item.get("url"),
                }
                for item in candidates[:10]
            ],
            "requires_human_review": True,
        }


def _self_test() -> int:
    import tempfile

    class FakeResult:
        def __init__(self, payload: Mapping[str, Any]) -> None:
            self.payload = dict(payload)

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        scope = SurfaceScope("fixture", "written authorization", allowed_domains=("example.com",), delay_seconds=0.1)
        payload = {
            "schema": "SrcSurfaceResult/v1",
            "target": "https://example.com/",
            "base_url": "https://example.com",
            "paths": ["/api/v1/users", "/admin/export?token=do-not-persist"],
            "api_urls": ["https://api.example.com/graphql"],
            "sources": {"/api/v1/users": ["openapi"]},
        }
        agent = SrcAutopilot(scope, root / "state.json", root / "out", max_rounds=4)
        first = agent.run_round(["https://example.com"], results=[payload])
        assert first["candidate_count"] == 3, first
        text = (root / "out" / "src-autopilot-candidates.json").read_text(encoding="utf-8")
        assert "do-not-persist" not in text and "token=[redacted]" in text, text
        second = agent.run_round(results=[payload])
        assert second["status"] == "awaiting_next_round", second
        third = agent.run_round(results=[payload])
        assert third["status"] == "stopped" and third["stop_reason"] == "converged_no_new_candidates", third
        restored = SrcAutopilot(scope, root / "state.json", root / "out", max_rounds=4)
        terminal = restored.run_round(results=[payload])
        assert terminal["event"] == "already_terminal", terminal
    print("src_autopilot self-test ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())
