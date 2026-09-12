"""Inbound /goal control flow: durable choice state and idempotent task launch."""
from __future__ import annotations

import json
import hashlib
import time
import uuid
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

from file_lock import AdvisoryFileLock
from goal_manager import GoalManager
from intake_state import (
    DEFAULT_INTAKE_TTL_SECONDS,
    IntakeState,
    IntakeStateError,
    TargetCardStore,
    canonical_digest,
    target_card_from_preview,
)
from operation_profile import (
    PROFILE_SELECTION_ORDER,
    get_profile,
    prompt_strategy_selection,
    resolve_request,
)


DEFAULT_PENDING_TTL_SECONDS = 15 * 60
DEFAULT_CLAIM_LEASE_SECONDS = 60


@dataclass(frozen=True)
class PendingProfileChoice:
    user_id: str
    chat_id: str
    message_id: str
    target: str
    instruction: str
    profile_ids: Tuple[str, ...]
    goal_id: str
    created_at: float
    expires_at: float
    claim_started_at: float = 0.0
    claim_id: str = ""

    @property
    def key(self) -> Tuple[str, str]:
        return self.user_id, self.chat_id

    def as_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "chat_id": self.chat_id,
            "message_id": self.message_id,
            "target": self.target,
            "instruction": self.instruction,
            "profile_ids": list(self.profile_ids),
            "goal_id": self.goal_id,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "claim_started_at": self.claim_started_at,
            "claim_id": self.claim_id,
        }


class GoalControl:
    """Keep profile selection separate from task execution.

    The pending stream has a small durable state machine: ``created -> claimed ->
    consumed`` or ``claim_failed``.  Task launch runs outside the pending lock and
    receives the goal ID as an idempotency key, so a failed post-submit audit write
    can be retried without creating a second task.
    """

    def __init__(
        self,
        *,
        goal_manager: GoalManager,
        task_manager: Any,
        pending_path: Path,
        now_fn: Optional[Callable[[], float]] = None,
        pending_ttl_seconds: int = DEFAULT_PENDING_TTL_SECONDS,
        claim_lease_seconds: int = DEFAULT_CLAIM_LEASE_SECONDS,
        intake_path: Optional[Path] = None,
        intake_ttl_seconds: int = DEFAULT_INTAKE_TTL_SECONDS,
        project_root: Optional[Path] = None,
    ) -> None:
        if pending_ttl_seconds <= 0:
            raise ValueError("pending_ttl_seconds must be positive")
        if claim_lease_seconds <= 0:
            raise ValueError("claim_lease_seconds must be positive")
        self.goal_manager = goal_manager
        self.task_manager = task_manager
        self.pending_path = Path(pending_path)
        self.project_root = Path(project_root) if project_root is not None else self.pending_path.parent
        self._lock_path = self.pending_path.with_name(self.pending_path.name + ".lock")
        self._now = now_fn or time.time
        self.pending_ttl_seconds = pending_ttl_seconds
        self.claim_lease_seconds = claim_lease_seconds
        self.intake_state = IntakeState(
            intake_path or self.pending_path.with_name("target_intakes.jsonl"),
            now_fn=self._now,
            ttl_seconds=intake_ttl_seconds,
        )
        self.target_card_store = TargetCardStore(self.project_root)
        self._pending: Dict[Tuple[str, str], PendingProfileChoice] = {}
        self._completed_requests: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        self._completed_replies: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        with self._pending_lock():
            self._reload_pending()

    def _pending_lock(self) -> AdvisoryFileLock:
        return AdvisoryFileLock(self._lock_path)

    def _append_pending_event(self, event: Dict[str, Any]) -> None:
        self.pending_path.parent.mkdir(parents=True, exist_ok=True)
        with self.pending_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")

    @staticmethod
    def _request_key(user_id: str, chat_id: str, message_id: str) -> Tuple[str, str, str]:
        return user_id, chat_id, message_id

    def _reload_pending(self) -> None:
        self._pending = {}
        self._completed_requests = {}
        self._completed_replies = {}
        if not self.pending_path.is_file():
            return
        for raw_line in self.pending_path.read_text(encoding="utf-8").splitlines():
            try:
                event = json.loads(raw_line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            kind = event.get("event")
            if kind == "created":
                data = event.get("pending")
                if not isinstance(data, dict):
                    continue
                try:
                    pending = PendingProfileChoice(
                        user_id=str(data["user_id"]),
                        chat_id=str(data["chat_id"]),
                        message_id=str(data.get("message_id", "")),
                        target=str(data["target"]),
                        instruction=str(data["instruction"]),
                        profile_ids=tuple(str(value) for value in data["profile_ids"]),
                        goal_id=str(data.get("goal_id") or ""),
                        created_at=float(data["created_at"]),
                        expires_at=float(data["expires_at"]),
                        claim_started_at=float(data.get("claim_started_at") or 0.0),
                        claim_id=str(data.get("claim_id") or ""),
                    )
                except (KeyError, TypeError, ValueError):
                    continue
                self._pending[pending.key] = pending
                continue

            key = (str(event.get("user_id", "")), str(event.get("chat_id", "")))
            pending = self._pending.get(key)
            if kind == "claimed" and pending is not None:
                self._pending[key] = replace(
                    pending,
                    claim_started_at=float(event.get("claimed_at") or 0.0),
                    claim_id=str(event.get("claim_id") or ""),
                )
            elif (
                kind == "claim_failed"
                and pending is not None
                and pending.claim_id == str(event.get("claim_id") or "")
            ):
                self._pending[key] = replace(pending, claim_started_at=0.0)
            elif kind == "consumed":
                if pending is not None and pending.claim_id != str(event.get("claim_id") or ""):
                    continue
                self._pending.pop(key, None)
                result = event.get("result")
                request_message_id = str(event.get("request_message_id", ""))
                if request_message_id and isinstance(result, dict):
                    durable_result = dict(result)
                    self._completed_requests[self._request_key(key[0], key[1], request_message_id)] = durable_result
                    reply_message_id = str(event.get("reply_message_id", ""))
                    if reply_message_id:
                        self._completed_replies[
                            self._request_key(key[0], key[1], reply_message_id)
                        ] = durable_result
            elif kind == "expired":
                self._pending.pop(key, None)

    def _create_pending(
        self,
        *,
        target: str,
        instruction: str,
        user_id: str,
        chat_id: str,
        message_id: str,
        profile_ids: Tuple[str, ...] = PROFILE_SELECTION_ORDER,
    ) -> PendingProfileChoice:
        now = float(self._now())
        pending = PendingProfileChoice(
            user_id=user_id,
            chat_id=chat_id,
            message_id=message_id,
            target=target,
            instruction=instruction,
            profile_ids=profile_ids,
            goal_id=f"G-{uuid.uuid4().hex[:12]}",
            created_at=now,
            expires_at=now + self.pending_ttl_seconds,
        )
        self._append_pending_event({"event": "created", "pending": pending.as_dict()})
        self._pending[pending.key] = pending
        return pending

    def _prompt_response(self, pending: PendingProfileChoice, *, reason: str = "") -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "state": "profile_choice",
            "target": pending.target,
            "profiles": list(pending.profile_ids),
            "prompt": prompt_strategy_selection(pending.profile_ids),
        }
        if reason:
            result["reason"] = reason
        return result

    @staticmethod
    def _intake_preview_response(preview: Any) -> Dict[str, Any]:
        return {
            "state": "intake_preview",
            "target": preview.target,
            "profile": preview.profile_name,
            "goal_id": preview.goal_id,
            "preview": preview.as_preview(),
        }

    @staticmethod
    def _starting_response(pending: PendingProfileChoice) -> Dict[str, Any]:
        profile = pending.profile_ids[0] if len(pending.profile_ids) == 1 else None
        return {
            "state": "starting",
            "target": pending.target,
            "profile": profile,
            "goal_id": pending.goal_id,
        }

    @staticmethod
    def _state_error(exc: OSError) -> Dict[str, Any]:
        return {
            "state": "state_error",
            "reason": "state_store_unavailable",
            "error": f"{type(exc).__name__}:{exc}",
        }

    def accept_goal_request(
        self,
        instruction: str,
        *,
        user_id: str,
        chat_id: str,
        message_id: str,
    ) -> Dict[str, Any]:
        try:
            return self._accept_goal_request(
                instruction,
                user_id=user_id,
                chat_id=chat_id,
                message_id=message_id,
            )
        except OSError as exc:
            return self._state_error(exc)

    def _accept_goal_request(
        self,
        instruction: str,
        *,
        user_id: str,
        chat_id: str,
        message_id: str,
    ) -> Dict[str, Any]:
        decision = resolve_request(instruction)
        if decision.goal_exempt:
            return {
                "state": "limited_analysis",
                "target": decision.target,
                "instruction": decision.instruction,
            }
        if not decision.target:
            return {"state": "ignored", "reason": "missing_target"}

        with self._pending_lock():
            self._reload_pending()
            completed = self._completed_requests.get(self._request_key(user_id, chat_id, message_id))
            if completed is not None:
                return dict(completed)

            existing = self._pending.get((user_id, chat_id))
            now = float(self._now())
            if existing is not None and now >= existing.expires_at:
                self._append_pending_event(
                    {"event": "expired", "user_id": user_id, "chat_id": chat_id, "ts": now}
                )
                self._pending.pop(existing.key, None)
                existing = None
            if existing is not None:
                if existing.message_id != message_id:
                    return self._prompt_response(existing, reason="pending_profile_choice_exists")
                if len(existing.profile_ids) != 1:
                    return self._prompt_response(existing)
                pass
            elif decision.requires_profile_choice:
                pending = self._create_pending(
                    target=decision.target,
                    instruction=decision.instruction,
                    user_id=user_id,
                    chat_id=chat_id,
                    message_id=message_id,
                )
                reason = "conflicting_profile_selection" if decision.profile_conflict else ""
                return self._prompt_response(pending, reason=reason)
            elif decision.profile_name is not None:
                self._create_pending(
                    target=decision.target,
                    instruction=decision.instruction,
                    user_id=user_id,
                    chat_id=chat_id,
                    message_id=message_id,
                    profile_ids=(decision.profile_name,),
                )
            else:
                return {"state": "ignored", "reason": "missing_profile"}

        return self._launch_choice(
            "1",
            user_id=user_id,
            chat_id=chat_id,
            reply_message_id=message_id,
        )

    def consume_numeric_reply(
        self,
        reply: str,
        *,
        user_id: str,
        chat_id: str,
        message_id: str,
    ) -> Dict[str, Any]:
        try:
            return self._consume_numeric_reply(
                reply,
                user_id=user_id,
                chat_id=chat_id,
                message_id=message_id,
            )
        except OSError as exc:
            return self._state_error(exc)

    def pending_intake_preview(self, *, user_id: str, chat_id: str) -> Optional[Dict[str, Any]]:
        """Return the current redacted-by-caller preview for explicit confirmation routing."""
        try:
            preview = self.intake_state.pending(user_id=user_id, chat_id=chat_id)
        except OSError:
            return None
        return preview.as_preview() if preview is not None else None

    def _consume_numeric_reply(
        self,
        reply: str,
        *,
        user_id: str,
        chat_id: str,
        message_id: str,
    ) -> Dict[str, Any]:
        with self._pending_lock():
            self._reload_pending()
            completed = self._completed_replies.get(self._request_key(user_id, chat_id, message_id))
            if completed is not None:
                return dict(completed)
        return self._launch_choice(
            reply,
            user_id=user_id,
            chat_id=chat_id,
            reply_message_id=message_id,
        )

    def _launch_choice(
        self,
        reply: str,
        *,
        user_id: str,
        chat_id: str,
        reply_message_id: str,
    ) -> Dict[str, Any]:
        claimed: Optional[PendingProfileChoice] = None
        with self._pending_lock():
            self._reload_pending()
            pending = self._pending.get((user_id, chat_id))
            if pending is None:
                return {"state": "ignored", "reason": "no_pending_profile_choice"}
            now = float(self._now())
            if now >= pending.expires_at:
                self._append_pending_event(
                    {"event": "expired", "user_id": user_id, "chat_id": chat_id, "ts": now}
                )
                self._pending.pop(pending.key, None)
                return {"state": "expired", "reason": "profile_choice_expired"}
            try:
                choice = int(reply.strip())
            except (TypeError, ValueError):
                return self._prompt_response(pending, reason="invalid_profile_choice")
            if choice < 1 or choice > len(pending.profile_ids):
                return self._prompt_response(pending, reason="invalid_profile_choice")
            profile_name = pending.profile_ids[choice - 1]
            if get_profile(profile_name) is None:
                return self._prompt_response(pending, reason="profile_registry_changed")
            if pending.claim_started_at and now - pending.claim_started_at < self.claim_lease_seconds:
                return self._starting_response(pending)
            claimed = replace(pending, claim_started_at=now, claim_id=uuid.uuid4().hex)
            self._append_pending_event(
                {
                    "event": "claimed",
                    "user_id": user_id,
                    "chat_id": chat_id,
                    "claimed_at": now,
                    "claim_id": claimed.claim_id,
                }
            )
            self._pending[claimed.key] = claimed

        try:
            preview = self.intake_state.create_preview(
                target=claimed.target,
                instruction=claimed.instruction,
                profile_name=claimed.profile_ids[int(reply.strip()) - 1],
                goal_id=claimed.goal_id,
                user_id=user_id,
                chat_id=chat_id,
                message_id=reply_message_id,
            )
        except IntakeStateError as exc:
            self._mark_claim_failed(claimed)
            return {
                "state": "state_error",
                "reason": str(exc),
                "target": claimed.target,
                "profile": claimed.profile_ids[int(reply.strip()) - 1],
                "goal_id": claimed.goal_id,
            }
        result = self._intake_preview_response(preview)
        return self._mark_claim_consumed(claimed, result, reply_message_id=reply_message_id)

    def _mark_claim_failed(self, pending: PendingProfileChoice) -> None:
        with self._pending_lock():
            self._reload_pending()
            current = self._pending.get(pending.key)
            if (
                current is not None
                and current.goal_id == pending.goal_id
                and current.claim_id == pending.claim_id
            ):
                self._append_pending_event(
                    {
                        "event": "claim_failed",
                        "user_id": pending.user_id,
                        "chat_id": pending.chat_id,
                        "claim_id": pending.claim_id,
                        "ts": float(self._now()),
                    }
                )
                self._pending[pending.key] = replace(current, claim_started_at=0.0)

    def _mark_claim_consumed(
        self,
        pending: PendingProfileChoice,
        result: Dict[str, Any],
        *,
        reply_message_id: str,
    ) -> Dict[str, Any]:
        durable_result = {
            "state": result["state"],
            "target": result["target"],
            "profile": result["profile"],
            "goal_id": result["goal_id"],
        }
        if result.get("state") == "intake_preview" and isinstance(result.get("preview"), dict):
            durable_result["preview"] = dict(result["preview"])
        try:
            with self._pending_lock():
                self._reload_pending()
                current = self._pending.get(pending.key)
                if current is None:
                    completed = self._completed_requests.get(
                        self._request_key(pending.user_id, pending.chat_id, pending.message_id)
                    )
                    return dict(completed) if completed is not None else result
                if current.goal_id != pending.goal_id or current.claim_id != pending.claim_id:
                    return self._starting_response(current)
                self._append_pending_event(
                    {
                        "event": "consumed",
                        "user_id": pending.user_id,
                        "chat_id": pending.chat_id,
                        "claim_id": pending.claim_id,
                        "request_message_id": pending.message_id,
                        "reply_message_id": reply_message_id,
                        "result": durable_result,
                        "ts": float(self._now()),
                    }
                )
                self._pending.pop(pending.key, None)
                self._completed_requests[
                    self._request_key(pending.user_id, pending.chat_id, pending.message_id)
                ] = durable_result
                if reply_message_id:
                    self._completed_replies[
                        self._request_key(pending.user_id, pending.chat_id, reply_message_id)
                    ] = durable_result
                return result
        except OSError as exc:
            uncertain = {
                "state": result["state"],
                "target": result["target"],
                "profile": result["profile"],
                "goal_id": result["goal_id"],
                "error": f"{type(exc).__name__}:{exc}",
            }
            if result.get("state") == "intake_preview" and isinstance(result.get("preview"), dict):
                uncertain["preview"] = dict(result["preview"])
            return uncertain

    def _start(
        self,
        *,
        target: str,
        instruction: str,
        profile_name: str,
        user_id: str,
        chat_id: str,
        target_card: Optional[Dict[str, Any]] = None,
        target_card_digest: str = "",
        target_card_ref: str = "",
        goal_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        target_card_digest = target_card_digest or str((target_card or {}).get("target_card_digest", ""))
        goal = self.goal_manager.create_goal(
            target=target,
            profile_name=profile_name,
            instruction=instruction,
            target_id=str((target_card or {}).get("target_id", "")),
            target_card_digest=target_card_digest,
            goal_id=goal_id,
        )
        task = None
        if self.task_manager is not None:
            try:
                task = self.task_manager.submit(
                    target,
                    instruction,
                    user_id=user_id,
                    chat_id=chat_id,
                    goal_id=goal.goal_id,
                    profile_name=profile_name,
                    target_id=str((target_card or {}).get("target_id", "")),
                    target_card_digest=target_card_digest,
                    idempotency_key=goal.goal_id,
                )
            except Exception as exc:
                return {
                    "state": "task_error",
                    "target": target,
                    "profile": profile_name,
                    "goal_id": goal.goal_id,
                    "error": f"{type(exc).__name__}:{exc}",
                }
        return {
            "state": "started",
            "target": target,
            "profile": profile_name,
            "goal_id": goal.goal_id,
            "task": task,
            "target_card": target_card,
            "target_card_digest": target_card_digest or None,
            "target_id": str((target_card or {}).get("target_id", "")) or None,
            "target_card_ref": target_card_ref or None,
        }

    def consume_intake_confirmation(
        self,
        confirmation: str,
        *,
        user_id: str,
        chat_id: str,
        message_id: str,
    ) -> Dict[str, Any]:
        """Confirm the caller's current preview before materializing Goal/Task."""
        tokens = str(confirmation or "").strip().split()
        if len(tokens) != 3 or tokens[0].lower() not in {"confirm", "确认"}:
            return {"state": "intake_preview", "reason": "confirmation_required"}
        intake_id, options_digest = tokens[1], tokens[2].lower()
        try:
            replay = self.intake_state.confirmation_result(
                user_id=user_id, chat_id=chat_id, message_id=message_id
            )
            if replay is not None:
                if (
                    str(replay.get("intake_id", "")) != intake_id
                    or str(replay.get("options_digest", "")) != options_digest
                ):
                    return {"state": "state_error", "reason": "intake_confirmation_binding_mismatch"}
                return self._start_from_confirmed(replay, user_id=user_id, chat_id=chat_id)
            replay = self.intake_state.confirmed_intake(
                user_id=user_id,
                chat_id=chat_id,
                intake_id=intake_id,
                options_digest=options_digest,
            )
            if replay is not None:
                return self._start_from_confirmed(replay, user_id=user_id, chat_id=chat_id)
            preview = self.intake_state.pending(user_id=user_id, chat_id=chat_id)
            if preview is None:
                return {"state": "expired", "reason": "intake_preview_expired"}
            target_card = target_card_from_preview(preview)
            receipt = self.intake_state.consume_confirmation(
                user_id=user_id,
                chat_id=chat_id,
                message_id=message_id,
                intake_id=intake_id,
                options_digest=options_digest,
                target_card=target_card,
            )
            return self._start_from_confirmed(receipt, user_id=user_id, chat_id=chat_id)
        except IntakeStateError as exc:
            reason = str(exc)
            if reason in {"intake_preview_expired", "intake_confirmation_expired"}:
                return {"state": "expired", "reason": reason}
            return {"state": "state_error", "reason": reason}
        except OSError as exc:
            return self._state_error(exc)

    def _start_from_confirmed(self, receipt: Dict[str, Any], *, user_id: str, chat_id: str) -> Dict[str, Any]:
        target_card = receipt.get("target_card")
        if not isinstance(target_card, dict):
            return {"state": "state_error", "reason": "intake_receipt_invalid"}
        target = str(receipt.get("target", ""))
        profile_name = str(receipt.get("profile", ""))
        goal_id = str(receipt.get("goal_id", ""))
        instruction = str(receipt.get("instruction", ""))
        expected_instruction_digest = str(receipt.get("instruction_digest", ""))
        if not target or not profile_name or not goal_id or not instruction:
            return {"state": "state_error", "reason": "intake_receipt_invalid"}
        if expected_instruction_digest != hashlib.sha256(instruction.encode("utf-8")).hexdigest():
            return {"state": "state_error", "reason": "intake_receipt_invalid"}
        target_card_digest = str(receipt.get("target_card_digest", ""))
        if target_card_digest != canonical_digest(target_card):
            return {"state": "state_error", "reason": "intake_receipt_invalid"}
        receipt_scope_digest = str(receipt.get("scope_digest", ""))
        if target_card.get("scope") is None or receipt_scope_digest != canonical_digest(target_card["scope"]):
            return {"state": "state_error", "reason": "intake_receipt_invalid"}
        try:
            stored_card = self.target_card_store.materialize(target_card)
            if str(stored_card["target_card_digest"]) != target_card_digest:
                return {"state": "state_error", "reason": "canonical_target_card_mismatch"}
            result = self._start(
                target=target,
                instruction=instruction,
                profile_name=profile_name,
                goal_id=goal_id,
                user_id=user_id,
                chat_id=chat_id,
                target_card=stored_card["target_card"],
                target_card_digest=target_card_digest,
                target_card_ref=str(stored_card["target_card_ref"]),
            )
        except IntakeStateError as exc:
            return {"state": "state_error", "reason": str(exc)}
        except Exception as exc:
            return {
                "state": "task_error",
                "target": target,
                "profile": profile_name,
                "goal_id": goal_id,
                "error": f"{type(exc).__name__}:{exc}",
            }
        return result
