"""Append-only persistence and stop conditions for one /goal contract."""
from __future__ import annotations

import copy
import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from file_lock import AdvisoryFileLock


DEFAULT_TIMEBOX_SECONDS = 2 * 60 * 60


@dataclass
class GoalContract:
    goal_id: str
    target: str
    profile_name: str
    instruction: str
    created_at: float
    endpoints_total: int = 0
    timebox_seconds: int = DEFAULT_TIMEBOX_SECONDS
    target_id: str = ""
    target_card_digest: str = ""
    audited_endpoints: Set[str] = field(default_factory=set)
    findings: List[Dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "goal_id": self.goal_id,
            "target": self.target,
            "profile_name": self.profile_name,
            "instruction": self.instruction,
            "created_at": self.created_at,
            "endpoints_total": self.endpoints_total,
            "timebox_seconds": self.timebox_seconds,
            "target_id": self.target_id,
            "target_card_digest": self.target_card_digest,
        }


class GoalManager:
    """Reconstruct goal state from an append-only JSONL event stream.

    Every read-modify-write operation is protected by a sidecar advisory lock and
    rebuilds from disk while holding that lock.  This keeps independent consumer
    processes from creating divergent goal histories.
    """

    def __init__(
        self,
        goals_path: Path,
        *,
        now_fn: Optional[Callable[[], float]] = None,
    ) -> None:
        self.goals_path = Path(goals_path)
        self._lock_path = self.goals_path.with_name(self.goals_path.name + ".lock")
        self._now = now_fn or time.time
        self._goals: Dict[str, GoalContract] = {}
        with self._lock():
            self._reload()

    def _lock(self) -> AdvisoryFileLock:
        return AdvisoryFileLock(self._lock_path)

    def _append(self, event: Dict[str, Any]) -> None:
        self.goals_path.parent.mkdir(parents=True, exist_ok=True)
        with self.goals_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")

    def _reload(self) -> None:
        self._goals = {}
        if not self.goals_path.is_file():
            return
        for raw_line in self.goals_path.read_text(encoding="utf-8").splitlines():
            try:
                event = json.loads(raw_line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict):
                self._apply_event(event)

    def _apply_event(self, event: Dict[str, Any]) -> None:
        kind = event.get("event")
        if kind == "created":
            data = event.get("goal")
            if not isinstance(data, dict) or not data.get("goal_id"):
                return
            try:
                goal = GoalContract(
                    goal_id=str(data["goal_id"]),
                    target=str(data.get("target", "")),
                    profile_name=str(data.get("profile_name", "")),
                    instruction=str(data.get("instruction", "")),
                    created_at=float(data.get("created_at", 0.0)),
                    endpoints_total=int(data.get("endpoints_total", 0)),
                    timebox_seconds=int(data.get("timebox_seconds", DEFAULT_TIMEBOX_SECONDS)),
                    target_id=str(data.get("target_id", "")),
                    target_card_digest=str(data.get("target_card_digest", "")),
                )
            except (TypeError, ValueError):
                return
            self._goals[goal.goal_id] = goal
            return

        goal = self._goals.get(str(event.get("goal_id", "")))
        if goal is None:
            return
        if kind == "endpoint_audited":
            endpoint = event.get("endpoint")
            if isinstance(endpoint, str) and endpoint:
                goal.audited_endpoints.add(endpoint)
        elif kind == "finding_recorded":
            finding = event.get("finding")
            if isinstance(finding, dict):
                goal.findings.append(copy.deepcopy(finding))

    @staticmethod
    def _snapshot(goal: GoalContract) -> GoalContract:
        return GoalContract(
            goal_id=goal.goal_id,
            target=goal.target,
            profile_name=goal.profile_name,
            instruction=goal.instruction,
            created_at=goal.created_at,
            endpoints_total=goal.endpoints_total,
            timebox_seconds=goal.timebox_seconds,
            target_id=goal.target_id,
            target_card_digest=goal.target_card_digest,
            audited_endpoints=set(goal.audited_endpoints),
            findings=copy.deepcopy(goal.findings),
        )

    @staticmethod
    def _same_contract(
        goal: GoalContract,
        *,
        target: str,
        profile_name: str,
        instruction: str,
        endpoints_total: int,
        timebox_seconds: int,
        target_id: str,
        target_card_digest: str,
    ) -> bool:
        return (
            goal.target == target
            and goal.profile_name == profile_name
            and goal.instruction == instruction
            and goal.endpoints_total == endpoints_total
            and goal.timebox_seconds == timebox_seconds
            and goal.target_id == target_id
            and goal.target_card_digest == target_card_digest
        )

    def create_goal(
        self,
        *,
        target: str,
        profile_name: str,
        instruction: str,
        endpoints_total: int = 0,
        timebox_seconds: int = DEFAULT_TIMEBOX_SECONDS,
        target_id: str = "",
        target_card_digest: str = "",
        goal_id: Optional[str] = None,
    ) -> GoalContract:
        target = target.strip()
        profile_name = profile_name.strip()
        if not target:
            raise ValueError("target is required")
        if not profile_name:
            raise ValueError("profile_name is required")
        if endpoints_total < 0:
            raise ValueError("endpoints_total must be non-negative")
        if timebox_seconds <= 0:
            raise ValueError("timebox_seconds must be positive")
        target_card_digest = target_card_digest.strip().lower()
        target_id = target_id.strip()
        if not target_id or not target_card_digest:
            raise ValueError("target_identity_binding_required")
        if (
            len(target_card_digest) != 64
            or any(character not in "0123456789abcdef" for character in target_card_digest)
        ):
            raise ValueError("target_card_digest_invalid")

        requested_id = goal_id or f"G-{uuid.uuid4().hex[:12]}"
        with self._lock():
            self._reload()
            existing = self._goals.get(requested_id)
            if existing is not None:
                if not self._same_contract(
                    existing,
                    target=target,
                    profile_name=profile_name,
                    instruction=instruction,
                    endpoints_total=endpoints_total,
                    timebox_seconds=timebox_seconds,
                    target_id=target_id,
                    target_card_digest=target_card_digest,
                ):
                    raise ValueError(f"goal_id_conflict:{requested_id}")
                return self._snapshot(existing)

            goal = GoalContract(
                goal_id=requested_id,
                target=target,
                profile_name=profile_name,
                instruction=instruction,
                created_at=float(self._now()),
                endpoints_total=endpoints_total,
                timebox_seconds=timebox_seconds,
                target_id=target_id,
                target_card_digest=target_card_digest,
            )
            event = {"event": "created", "goal": goal.as_dict()}
            self._append(event)
            self._apply_event(event)
            return self._snapshot(goal)

    def get_goal(self, goal_id: str) -> GoalContract:
        with self._lock():
            self._reload()
            try:
                return self._snapshot(self._goals[goal_id])
            except KeyError as exc:
                raise KeyError(f"unknown goal: {goal_id}") from exc

    def mark_endpoint_audited(self, goal_id: str, endpoint: str) -> bool:
        endpoint = endpoint.strip()
        if not endpoint:
            raise ValueError("endpoint is required")
        with self._lock():
            self._reload()
            goal = self._goals.get(goal_id)
            if goal is None:
                raise KeyError(f"unknown goal: {goal_id}")
            if endpoint in goal.audited_endpoints:
                return False
            event = {
                "event": "endpoint_audited",
                "goal_id": goal_id,
                "endpoint": endpoint,
                "ts": float(self._now()),
            }
            self._append(event)
            self._apply_event(event)
            return True

    def record_finding(self, goal_id: str, finding: Dict[str, Any]) -> None:
        with self._lock():
            self._reload()
            if goal_id not in self._goals:
                raise KeyError(f"unknown goal: {goal_id}")
            event = {
                "event": "finding_recorded",
                "goal_id": goal_id,
                "finding": copy.deepcopy(finding),
                "ts": float(self._now()),
            }
            self._append(event)
            self._apply_event(event)

    @staticmethod
    def _timebox_reason(goal: GoalContract) -> str:
        if goal.timebox_seconds == DEFAULT_TIMEBOX_SECONDS:
            return "timebox_2h"
        return f"timebox_{goal.timebox_seconds}s"

    def check_stop_conditions(self, goal_id: str) -> Optional[str]:
        with self._lock():
            self._reload()
            goal = self._goals.get(goal_id)
            if goal is None:
                raise KeyError(f"unknown goal: {goal_id}")
            if any(
                str(finding.get("type", "")).lower() in {"rce", "remote_code_execution"}
                and finding.get("verified") is True
                for finding in goal.findings
            ):
                return "rce_confirmed"
            if goal.endpoints_total > 0 and len(goal.audited_endpoints) >= goal.endpoints_total:
                return "all_endpoints_audited"
            if float(self._now()) - goal.created_at >= goal.timebox_seconds:
                return self._timebox_reason(goal)
            return None
