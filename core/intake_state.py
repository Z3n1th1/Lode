"""Durable, confirmation-bound intake state for a new target.

The intake layer deliberately creates no network activity.  It normalizes one
requested target, exposes explicitly disabled integration switches, and only
materializes a minimal TargetCard after the same caller confirms the immutable
preview digest.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import urlsplit

from file_lock import AdvisoryFileLock

try:
    import yaml
except ImportError:  # JSON-compatible cards remain readable without the optional parser.
    yaml = None


DEFAULT_INTAKE_TTL_SECONDS = 15 * 60
_DIGEST_RE = re.compile(r"[0-9a-f]{64}")
_HOST_RE = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", re.IGNORECASE)
_IPV4_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
_SAFE_ID_RE = re.compile(r"[^a-z0-9]+")
_TARGET_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_CANONICAL_SCHEMA_VALIDATOR_PATH = (
    Path(__file__).resolve().parents[2]
    / "skills"
    / "ai-pentest-matrix"
    / "scripts"
    / "schema_validator.py"
)
_CANONICAL_SCHEMA_VALIDATOR = None
_CANONICAL_SCHEMA_VALIDATOR_LOCK = threading.Lock()


class IntakeStateError(ValueError):
    """The append-only intake state cannot produce a safe next transition."""


def canonical_digest(value: Dict[str, Any]) -> str:
    """Match the shared target_scope canonical JSON digest contract."""
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _normalized_target(target: str) -> Tuple[str, str, str]:
    """Return display target, canonical host and entrypoint without contacting it."""
    value = target.strip()
    if not value:
        raise IntakeStateError("intake_target_required")
    candidate = value if "://" in value else f"https://{value}"
    parsed = urlsplit(candidate)
    host = (parsed.hostname or "").strip().rstrip(".").lower()
    if not host or (_IPV4_RE.fullmatch(host) is None and _HOST_RE.fullmatch(host) is None):
        raise IntakeStateError("intake_target_invalid")
    if any(part.isdigit() and not 0 <= int(part) <= 255 for part in host.split(".")):
        raise IntakeStateError("intake_target_invalid")
    scheme = parsed.scheme.lower() if parsed.scheme.lower() in {"http", "https"} else "https"
    port = f":{parsed.port}" if parsed.port is not None else ""
    path = parsed.path or "/"
    entrypoint = f"{scheme}://{host}{port}{path}"
    return value, host, entrypoint


def _target_id(host: str) -> str:
    compact = _SAFE_ID_RE.sub("-", host.lower()).strip("-")[:48] or "target"
    return f"{compact}-{hashlib.sha256(host.encode('utf-8')).hexdigest()[:12]}"


@dataclass(frozen=True)
class IntakePreview:
    intake_id: str
    user_id: str
    chat_id: str
    message_id: str
    target: str
    canonical_host: str
    entrypoint: str
    instruction: str
    instruction_digest: str
    profile_name: str
    goal_id: str
    created_at: float
    expires_at: float
    options: Dict[str, Any]
    scope_digest: str
    options_digest: str
    preview_digest: str
    confirmation_message_id: str = ""

    @property
    def key(self) -> Tuple[str, str]:
        return self.user_id, self.chat_id

    def as_preview(self) -> Dict[str, Any]:
        return {
            "schema": "TargetIntakePreview/v1",
            "intake_id": self.intake_id,
            "target": self.target,
            "canonical_host": self.canonical_host,
            "entrypoint": self.entrypoint,
            "instruction_digest": self.instruction_digest,
            "profile_name": self.profile_name,
            "goal_id": self.goal_id,
            "scope_digest": self.scope_digest,
            "options": self.options,
            "options_digest": self.options_digest,
            "preview_digest": self.preview_digest,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }

    def as_event(self) -> Dict[str, Any]:
        return {
            "intake_id": self.intake_id,
            "user_id": self.user_id,
            "chat_id": self.chat_id,
            "message_id": self.message_id,
            "target": self.target,
            "canonical_host": self.canonical_host,
            "entrypoint": self.entrypoint,
            "instruction": self.instruction,
            "instruction_digest": self.instruction_digest,
            "profile_name": self.profile_name,
            "goal_id": self.goal_id,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "options": self.options,
            "scope_digest": self.scope_digest,
            "options_digest": self.options_digest,
            "preview_digest": self.preview_digest,
            "confirmation_message_id": self.confirmation_message_id,
        }


def _default_options() -> Dict[str, Any]:
    return {
        "asset_inventory": {"enabled": False, "mode": "not_requested"},
        "fingerprint": {"enabled": False, "mode": "not_requested"},
        "arl_next": {"enabled": False, "mode": "not_available"},
        "intelligence": {"enabled": False, "mode": "metadata_only"},
        "poc_research": {"enabled": False, "mode": "metadata_only"},
        "proxy_route": {"enabled": False, "profile": ""},
    }


class IntakeState:
    """One pending preview per trusted user/chat, replayed from append-only JSONL."""

    def __init__(
        self,
        path: Path | str,
        *,
        now_fn: Optional[Callable[[], float]] = None,
        ttl_seconds: int = DEFAULT_INTAKE_TTL_SECONDS,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("intake_ttl_seconds_must_be_positive")
        self.path = Path(path)
        self._lock_path = self.path.with_name(self.path.name + ".lock")
        self._now = now_fn or time.time
        self.ttl_seconds = ttl_seconds
        self._pending: Dict[Tuple[str, str], IntakePreview] = {}
        self._completed_by_message: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        self._completed_by_intake: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        with self._lock():
            self._reload()

    def _lock(self) -> AdvisoryFileLock:
        return AdvisoryFileLock(self._lock_path)

    def _append(self, event: Dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")

    def _reload(self) -> None:
        self._pending = {}
        self._completed_by_message = {}
        self._completed_by_intake = {}
        if not self.path.is_file():
            return
        for raw_line in self.path.read_text(encoding="utf-8").splitlines():
            try:
                event = json.loads(raw_line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            kind = event.get("event")
            if kind == "preview_created":
                data = event.get("preview")
                preview = self._parse_preview(data)
                if preview is not None:
                    self._pending[preview.key] = preview
                continue
            user_id = str(event.get("user_id", ""))
            chat_id = str(event.get("chat_id", ""))
            key = (user_id, chat_id)
            if kind == "preview_expired":
                self._pending.pop(key, None)
            elif kind == "confirmed":
                self._pending.pop(key, None)
                message_id = str(event.get("message_id", ""))
                result = event.get("result")
                if message_id and isinstance(result, dict):
                    self._completed_by_message[(user_id, chat_id, message_id)] = dict(result)
                intake_id = str(event.get("intake_id", ""))
                if intake_id and isinstance(result, dict):
                    self._completed_by_intake[(user_id, chat_id, intake_id)] = dict(result)

    @staticmethod
    def _parse_preview(value: Any) -> Optional[IntakePreview]:
        if not isinstance(value, dict):
            return None
        try:
            options = value["options"]
            if not isinstance(options, dict):
                return None
            preview = IntakePreview(
                intake_id=str(value["intake_id"]),
                user_id=str(value["user_id"]),
                chat_id=str(value["chat_id"]),
                message_id=str(value.get("message_id", "")),
                target=str(value["target"]),
                canonical_host=str(value["canonical_host"]),
                entrypoint=str(value["entrypoint"]),
                instruction=str(value["instruction"]),
                instruction_digest=str(value["instruction_digest"]),
                profile_name=str(value["profile_name"]),
                goal_id=str(value["goal_id"]),
                created_at=float(value["created_at"]),
                expires_at=float(value["expires_at"]),
                options=options,
                scope_digest=str(value["scope_digest"]),
                options_digest=str(value["options_digest"]),
                preview_digest=str(value["preview_digest"]),
                confirmation_message_id=str(value.get("confirmation_message_id", "")),
            )
        except (KeyError, TypeError, ValueError):
            return None
        if not preview.intake_id or not preview.user_id or not preview.chat_id:
            return None
        if any(_DIGEST_RE.fullmatch(item) is None for item in (preview.scope_digest, preview.options_digest, preview.preview_digest)):
            return None
        if preview.instruction_digest != hashlib.sha256(preview.instruction.encode("utf-8")).hexdigest():
            return None
        expected = canonical_digest({key: value for key, value in preview.as_preview().items() if key != "preview_digest"})
        return preview if expected == preview.preview_digest else None

    @staticmethod
    def _scope(host: str) -> Dict[str, Any]:
        return {"allowed_hosts": [host], "forbidden_hosts": []}

    def create_preview(
        self,
        *,
        target: str,
        instruction: str,
        profile_name: str,
        goal_id: str,
        user_id: str,
        chat_id: str,
        message_id: str,
    ) -> IntakePreview:
        display_target, host, entrypoint = _normalized_target(target)
        profile_name = profile_name.strip()
        goal_id = goal_id.strip()
        if not profile_name or not goal_id:
            raise IntakeStateError("intake_profile_and_goal_required")
        now = float(self._now())
        scope_digest = canonical_digest(self._scope(host))
        options = _default_options()
        options_digest = canonical_digest(options)
        instruction_digest = hashlib.sha256(instruction.encode("utf-8")).hexdigest()
        base = {
            "schema": "TargetIntakePreview/v1",
            "intake_id": f"I-{uuid.uuid4().hex[:12]}",
            "target": display_target,
            "canonical_host": host,
            "entrypoint": entrypoint,
            "instruction_digest": instruction_digest,
            "profile_name": profile_name,
            "goal_id": goal_id,
            "scope_digest": scope_digest,
            "options": options,
            "options_digest": options_digest,
            "created_at": now,
            "expires_at": now + self.ttl_seconds,
        }
        preview = IntakePreview(
            intake_id=str(base["intake_id"]),
            user_id=user_id,
            chat_id=chat_id,
            message_id=message_id,
            target=display_target,
            canonical_host=host,
            entrypoint=entrypoint,
            instruction=instruction,
            instruction_digest=instruction_digest,
            profile_name=profile_name,
            goal_id=goal_id,
            created_at=now,
            expires_at=now + self.ttl_seconds,
            options=options,
            scope_digest=scope_digest,
            options_digest=options_digest,
            preview_digest=canonical_digest(base),
        )
        with self._lock():
            self._reload()
            existing = self._pending.get(preview.key)
            if existing is not None and now < existing.expires_at:
                if (
                    existing.target == preview.target
                    and existing.instruction_digest == preview.instruction_digest
                    and existing.profile_name == preview.profile_name
                    and existing.goal_id == preview.goal_id
                ):
                    return existing
                raise IntakeStateError("pending_intake_exists")
            if existing is not None:
                self._append({"event": "preview_expired", "user_id": user_id, "chat_id": chat_id, "ts": now})
            self._append({"event": "preview_created", "preview": preview.as_event()})
            self._pending[preview.key] = preview
        return preview

    def pending(self, *, user_id: str, chat_id: str) -> Optional[IntakePreview]:
        with self._lock():
            self._reload()
            preview = self._pending.get((user_id, chat_id))
            if preview is None:
                return None
            if float(self._now()) >= preview.expires_at:
                self._append({"event": "preview_expired", "user_id": user_id, "chat_id": chat_id, "ts": float(self._now())})
                self._pending.pop((user_id, chat_id), None)
                return None
            return preview

    def confirmation_result(self, *, user_id: str, chat_id: str, message_id: str) -> Optional[Dict[str, Any]]:
        with self._lock():
            self._reload()
            value = self._completed_by_message.get((user_id, chat_id, message_id))
            return dict(value) if value is not None else None

    def confirmed_intake(
        self,
        *,
        user_id: str,
        chat_id: str,
        intake_id: str,
        options_digest: str,
    ) -> Optional[Dict[str, Any]]:
        """Return a matching consumed receipt for crash/retry recovery only."""
        with self._lock():
            self._reload()
            value = self._completed_by_intake.get((user_id, chat_id, intake_id))
            if value is None:
                return None
            if str(value.get("options_digest", "")) != options_digest:
                raise IntakeStateError("intake_confirmation_binding_mismatch")
            try:
                expires_at = float(value["expires_at"])
            except (KeyError, TypeError, ValueError) as exc:
                raise IntakeStateError("intake_confirmation_expired") from exc
            if float(self._now()) >= expires_at:
                raise IntakeStateError("intake_confirmation_expired")
            return dict(value)

    def consume_confirmation(
        self,
        *,
        user_id: str,
        chat_id: str,
        message_id: str,
        intake_id: str,
        options_digest: str,
        target_card: Dict[str, Any],
    ) -> Dict[str, Any]:
        with self._lock():
            self._reload()
            replay = self._completed_by_message.get((user_id, chat_id, message_id))
            if replay is not None:
                if (
                    str(replay.get("intake_id", "")) != intake_id
                    or str(replay.get("options_digest", "")) != options_digest
                ):
                    raise IntakeStateError("intake_confirmation_binding_mismatch")
                return dict(replay)
            preview = self._pending.get((user_id, chat_id))
            if preview is None:
                raise IntakeStateError("no_pending_intake_preview")
            if float(self._now()) >= preview.expires_at:
                self._append({"event": "preview_expired", "user_id": user_id, "chat_id": chat_id, "ts": float(self._now())})
                self._pending.pop(preview.key, None)
                raise IntakeStateError("intake_preview_expired")
            if intake_id != preview.intake_id or options_digest != preview.options_digest:
                raise IntakeStateError("intake_confirmation_binding_mismatch")
            result = {
                "state": "confirmed",
                "intake_id": preview.intake_id,
                "target_card": target_card,
                "target_card_digest": canonical_digest(target_card),
                "target_id": str(target_card.get("target_id", "")),
                "profile": preview.profile_name,
                "goal_id": preview.goal_id,
                "target": preview.target,
                "instruction": preview.instruction,
                "instruction_digest": preview.instruction_digest,
                "scope_digest": preview.scope_digest,
                "options_digest": preview.options_digest,
                "expires_at": preview.expires_at,
            }
            self._append(
                {
                    "event": "confirmed",
                    "user_id": user_id,
                    "chat_id": chat_id,
                    "message_id": message_id,
                    "intake_id": preview.intake_id,
                    "preview_digest": preview.preview_digest,
                    "options_digest": preview.options_digest,
                    "result": result,
                    "ts": float(self._now()),
                }
            )
            self._pending.pop(preview.key, None)
            self._completed_by_message[(user_id, chat_id, message_id)] = dict(result)
            return result


def target_card_from_preview(preview: IntakePreview) -> Dict[str, Any]:
    """Build a stable scope card; the receipt retains the requested entrypoint."""
    card = {
        "schema": "TargetCard/v1",
        "target_id": _target_id(preview.canonical_host),
        "scenario": "unclassified",
        "scope": IntakeState._scope(preview.canonical_host),
        "entrypoints": [],
        "auth": {"required": False, "session_aliases": []},
        "notes": "Created from confirmed TargetIntakePreview/v1; no adapter or target request has run.",
    }
    return card


def _target_card_ref(target_id: str) -> str:
    """Return the canonical runtime-relative path for one immutable TargetCard."""
    if _TARGET_ID_RE.fullmatch(target_id) is None:
        raise IntakeStateError("target_card_id_invalid")
    return f"ai-pentest-evidence/projects/{target_id}/target.yaml"


def _canonical_target_card_bytes(target_card: Dict[str, Any]) -> bytes:
    """Use a deterministic JSON representation while the shared runtime stays JSON-compatible YAML."""
    return (json.dumps(target_card, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


class TargetCardStore:
    """Create one schema-compatible TargetCard once and detect later drift.

    This is deliberately a narrow persistence adapter. It never upgrades scope,
    changes existing target data, or contacts a target. A later signed authority
    layer may replace the trust model, but all consumers already bind the stable
    runtime-relative reference and canonical object digest.
    """

    def __init__(self, project_root: Path | str) -> None:
        self.project_root = Path(project_root)
        self._lock_path = self.project_root / "ai-pentest-evidence" / "projects" / ".target-cards.lock"

    def _lock(self) -> AdvisoryFileLock:
        return AdvisoryFileLock(self._lock_path)

    @staticmethod
    def _canonical_schema_errors(target_card: Dict[str, Any]) -> list[str]:
        global _CANONICAL_SCHEMA_VALIDATOR
        with _CANONICAL_SCHEMA_VALIDATOR_LOCK:
            if _CANONICAL_SCHEMA_VALIDATOR is None:
                if not _CANONICAL_SCHEMA_VALIDATOR_PATH.is_file():
                    # Standalone distributions do not include the optional
                    # skills checkout.  Keep the same required contract local
                    # so intake remains usable without silently accepting a
                    # weaker card shape.
                    return TargetCardStore._builtin_schema_errors(target_card)
                spec = importlib.util.spec_from_file_location(
                    "pentest_agent_canonical_schema_validator", _CANONICAL_SCHEMA_VALIDATOR_PATH
                )
                if spec is None or spec.loader is None:
                    raise IntakeStateError("canonical_target_card_schema_unavailable")
                module = importlib.util.module_from_spec(spec)
                sys.modules[spec.name] = module
                try:
                    spec.loader.exec_module(module)
                except Exception as exc:
                    sys.modules.pop(spec.name, None)
                    raise IntakeStateError("canonical_target_card_schema_unavailable") from exc
                _CANONICAL_SCHEMA_VALIDATOR = module
            try:
                return list(
                    _CANONICAL_SCHEMA_VALIDATOR.validate_doc(
                        target_card, _CANONICAL_SCHEMA_VALIDATOR.load_default_contracts()
                    )
                )
            except Exception as exc:
                raise IntakeStateError("canonical_target_card_schema_unavailable") from exc

    @staticmethod
    def _builtin_schema_errors(target_card: Dict[str, Any]) -> list[str]:
        """Validate the stable TargetCard/v1 subset used by this project.

        This mirrors the fields consumed by the canonical validator and is only
        used when that validator is absent from a standalone checkout.
        """
        errors: list[str] = []
        if not isinstance(target_card, dict):
            return ["card_not_object"]
        if target_card.get("schema") != "TargetCard/v1":
            errors.append("schema")
        if not isinstance(target_card.get("target_id"), str):
            errors.append("target_id")
        if not isinstance(target_card.get("scenario", ""), str):
            errors.append("scenario")
        scope = target_card.get("scope")
        if not isinstance(scope, dict):
            errors.append("scope")
        else:
            for key in ("allowed_hosts", "forbidden_hosts"):
                hosts = scope.get(key)
                if not isinstance(hosts, list) or not all(isinstance(host, str) and host for host in hosts):
                    errors.append(f"scope.{key}")
        entrypoints = target_card.get("entrypoints", [])
        if not isinstance(entrypoints, list) or not all(isinstance(item, str) and item for item in entrypoints):
            errors.append("entrypoints")
        auth = target_card.get("auth", {})
        if not isinstance(auth, dict):
            errors.append("auth")
        elif not isinstance(auth.get("required"), bool) or not isinstance(auth.get("session_aliases"), list):
            errors.append("auth")
        return errors

    @staticmethod
    def _validate_target_card(target_card: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(target_card, dict):
            raise IntakeStateError("target_card_invalid")
        if TargetCardStore._canonical_schema_errors(target_card):
            raise IntakeStateError("target_card_schema_invalid")
        target_id = str(target_card.get("target_id", ""))
        if _TARGET_ID_RE.fullmatch(target_id) is None:
            raise IntakeStateError("target_card_schema_invalid")
        scope = target_card.get("scope")
        if not isinstance(scope, dict):
            raise IntakeStateError("target_card_schema_invalid")
        for key in ("allowed_hosts", "forbidden_hosts"):
            hosts = scope.get(key)
            if not isinstance(hosts, list) or not all(isinstance(host, str) and host for host in hosts):
                raise IntakeStateError("target_card_schema_invalid")
            if len(hosts) != len(set(hosts)):
                raise IntakeStateError("target_card_schema_invalid")
        if not isinstance(target_card.get("entrypoints", []), list):
            raise IntakeStateError("target_card_schema_invalid")
        auth = target_card.get("auth", {})
        if not isinstance(auth, dict):
            raise IntakeStateError("target_card_schema_invalid")
        if not isinstance(auth.get("required"), bool) or not isinstance(auth.get("session_aliases"), list):
            raise IntakeStateError("target_card_schema_invalid")
        return dict(target_card)

    @staticmethod
    def _read_existing(path: Path, *, expected_digest: str, target_id: str, relative_ref: str) -> Dict[str, Any]:
        if not path.is_file() or path.is_symlink():
            raise IntakeStateError("canonical_target_card_unavailable")
        try:
            raw = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise IntakeStateError("canonical_target_card_unavailable") from exc
        if yaml is None:
            try:
                existing = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise IntakeStateError("canonical_target_card_unavailable") from exc
        else:
            try:
                existing = yaml.safe_load(raw)
            except yaml.YAMLError as exc:
                raise IntakeStateError("canonical_target_card_unavailable") from exc
        try:
            existing_card = TargetCardStore._validate_target_card(existing)
        except IntakeStateError as exc:
            raise IntakeStateError("canonical_target_card_mismatch") from exc
        if canonical_digest(existing_card) != expected_digest:
            raise IntakeStateError("canonical_target_card_mismatch")
        return {
            "target_card": existing_card,
            "target_card_digest": expected_digest,
            "target_id": target_id,
            "target_card_ref": relative_ref,
        }

    def materialize(self, target_card: Dict[str, Any]) -> Dict[str, Any]:
        """Create the canonical file once or require the stored object to match exactly."""
        card = self._validate_target_card(target_card)
        target_id = str(card["target_id"])
        relative_ref = _target_card_ref(target_id)
        path = self.project_root / relative_ref
        expected_digest = canonical_digest(card)
        expected_bytes = _canonical_target_card_bytes(card)
        with self._lock():
            if path.exists():
                return self._read_existing(
                    path,
                    expected_digest=expected_digest,
                    target_id=target_id,
                    relative_ref=relative_ref,
                )

            path.parent.mkdir(parents=True, exist_ok=True)
            try:
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                return self._read_existing(
                    path,
                    expected_digest=expected_digest,
                    target_id=target_id,
                    relative_ref=relative_ref,
                )
            except OSError as exc:
                raise IntakeStateError("canonical_target_card_unavailable") from exc
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(expected_bytes)
                    handle.flush()
                    os.fsync(handle.fileno())
            except OSError as exc:
                raise IntakeStateError("canonical_target_card_unavailable") from exc
        return {
            "target_card": card,
            "target_card_digest": expected_digest,
            "target_id": target_id,
            "target_card_ref": relative_ref,
        }
