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

try:  # package import (python -m console.server)
    from core.file_lock import AdvisoryFileLock
except ImportError:  # pragma: no cover - stripped checkout with core/ on sys.path
    from file_lock import AdvisoryFileLock  # type: ignore

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


# 一次授权文档跑动的旋钮。这几个值进了 ``options_digest``,所以操作员确认的就是
# 他当时看到的那一组数字 —— 上限、速率、能力,一个都不能在确认之后偷偷变。
_SCOPE_OPTION_KEYS = ("max_fanout", "requests_per_second", "allowed_methods", "allow_request_body")


@dataclass(frozen=True)
class ScopeIntakePreview:
    """一次待确认的**授权文档**。

    和 :class:`IntakePreview` 是两个类型而不是同一个多态体:那个的 ``preview_digest``
    是用 ``as_preview()`` 重算出来的(见 :meth:`IntakeState._parse_preview`),给它加
    字段会让**每一条**已写下的待确认 preview 校验失败 —— 升级的一瞬间,操作员手上
    那张卡就凭空消失了。

    ``document`` 是逐字原文,``summary`` 是给操作员看的派生摘要。两者分开存:摘要要能
    被渲染和翻译,而原文是唯一能证明"程序到底写了什么"的东西。摘要里的 ``hosts`` /
    ``forbidden_hosts`` 折进 ``scope_digest``,旋钮折进 ``options_digest`` —— 沿用
    target 那条路已有的两个词,不另造一套。
    """

    intake_id: str
    user_id: str
    chat_id: str
    message_id: str
    source: str
    document: Dict[str, Any]
    document_digest: str
    summary: Dict[str, Any]
    instruction: str
    instruction_digest: str
    created_at: float
    expires_at: float
    scope_digest: str
    options_digest: str
    preview_digest: str
    confirmation_message_id: str = ""

    @property
    def key(self) -> Tuple[str, str]:
        return self.user_id, self.chat_id

    @property
    def host_count(self) -> int:
        return len(self.summary.get("hosts") or [])

    def as_preview(self) -> Dict[str, Any]:
        return {
            "schema": "ScopeIntakePreview/v1",
            "intake_id": self.intake_id,
            "source": self.source,
            "document": self.document,
            "document_digest": self.document_digest,
            "summary": self.summary,
            "instruction_digest": self.instruction_digest,
            "scope_digest": self.scope_digest,
            "options_digest": self.options_digest,
            "preview_digest": self.preview_digest,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }

    def as_event(self) -> Dict[str, Any]:
        return {
            **self.as_preview(),
            "user_id": self.user_id,
            "chat_id": self.chat_id,
            "message_id": self.message_id,
            "instruction": self.instruction,
            "confirmation_message_id": self.confirmation_message_id,
        }


def default_options() -> Dict[str, Any]:
    """The canonical all-off options object.

    Public because every caller that collects switches has to start from this
    shape and flip ``enabled`` — deriving the modes independently is how a
    caller ends up confirming something the gate does not recognise.  A switch
    that a caller offers but this object has no key for is a switch that would be
    silently dropped, so the two lists must stay in step.
    """
    return {
        # 能力型开关:mode 写的是"开着的时候最多做到哪一层",不随开关变化。
        "asset_inventory": {"enabled": False, "mode": "not_requested"},
        "fingerprint": {"enabled": False, "mode": "not_requested"},
        "arl_next": {"enabled": False, "mode": "not_available"},
        "intelligence": {"enabled": False, "mode": "metadata_only"},
        "poc_research": {"enabled": False, "mode": "metadata_only"},
        "proxy_route": {"enabled": False, "profile": ""},
        # 纯开关:mode 只记"有没有人要过"。
        "active_scan": {"enabled": False, "mode": "not_requested"},
        "subdomain_enum": {"enabled": False, "mode": "not_requested"},
        "nuclei": {"enabled": False, "mode": "not_requested"},
        "tscan": {"enabled": False, "mode": "not_requested"},
        "network_gate": {"enabled": False, "mode": "not_requested"},
        "edge_human_gate": {"enabled": False, "mode": "not_requested"},
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
        self._scope_pending: Dict[Tuple[str, str], ScopeIntakePreview] = {}
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
        self._scope_pending = {}
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
            if kind == "scope_preview_created":
                data = event.get("preview")
                preview = self._parse_scope_preview(data)
                if preview is not None:
                    self._scope_pending[preview.key] = preview
                continue
            user_id = str(event.get("user_id", ""))
            chat_id = str(event.get("chat_id", ""))
            key = (user_id, chat_id)
            if kind == "preview_expired":
                # 一个槽:过期就是把这一格清空,两种 preview 一起走。
                self._pending.pop(key, None)
                self._scope_pending.pop(key, None)
            elif kind == "confirmed":
                self._pending.pop(key, None)
                self._scope_pending.pop(key, None)
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
    def _parse_scope_preview(value: Any) -> Optional[ScopeIntakePreview]:
        """Rebuild one document preview, or ``None`` if the line cannot be trusted.

        这条多一道 target preview 没有的检查:``document_digest`` 必须真的等于
        ``canonical_digest(document)``。原文和它的摘要分两个字段存,所以一行被手改
        之后,摘要字段有可能被顺手留着 —— 那正好是"审的人读到的授权"和"真要跑的那份"
        分开的地方,不能靠运气。
        """
        if not isinstance(value, dict):
            return None
        try:
            document = value["document"]
            summary = value["summary"]
            if not isinstance(document, dict) or not isinstance(summary, dict):
                return None
            preview = ScopeIntakePreview(
                intake_id=str(value["intake_id"]),
                user_id=str(value.get("user_id", "")),
                chat_id=str(value.get("chat_id", "")),
                message_id=str(value.get("message_id", "")),
                source=str(value.get("source", "")),
                document=dict(document),
                document_digest=str(value["document_digest"]),
                summary=dict(summary),
                instruction=str(value.get("instruction", "")),
                instruction_digest=str(value["instruction_digest"]),
                created_at=float(value["created_at"]),
                expires_at=float(value["expires_at"]),
                scope_digest=str(value["scope_digest"]),
                options_digest=str(value["options_digest"]),
                preview_digest=str(value["preview_digest"]),
                confirmation_message_id=str(value.get("confirmation_message_id", "")),
            )
        except (KeyError, TypeError, ValueError):
            return None
        if not preview.intake_id or not preview.user_id or not preview.chat_id:
            return None
        if any(
            _DIGEST_RE.fullmatch(item) is None
            for item in (preview.document_digest, preview.scope_digest,
                         preview.options_digest, preview.preview_digest)
        ):
            return None
        if preview.instruction_digest != hashlib.sha256(preview.instruction.encode("utf-8")).hexdigest():
            return None
        if canonical_digest(preview.document) != preview.document_digest:
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
        options: Optional[Dict[str, Any]] = None,
    ) -> IntakePreview:
        """Build the one pending preview for this (user, chat).

        ``options`` defaults to ``default_options()`` (everything off) — the callers
        that have no toggle UI keep that.  A caller that *does* collect toggles passes
        them here so they land in ``options_digest`` and the confirmation covers
        exactly what the operator was shown, instead of being silently dropped.
        """
        display_target, host, entrypoint = _normalized_target(target)
        profile_name = profile_name.strip()
        goal_id = goal_id.strip()
        if not profile_name or not goal_id:
            raise IntakeStateError("intake_profile_and_goal_required")
        now = float(self._now())
        scope_digest = canonical_digest(self._scope(host))
        options = dict(options) if isinstance(options, dict) and options else default_options()
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
            # 一个 Console 一个待确认槽 —— 两种 preview 抢同一格。不能说清"一样"就抛,
            # 而不是把操作员手上那张卡悄悄换掉。
            existing = self._pending.get(preview.key) or self._scope_pending.get(preview.key)
            if existing is not None and now < existing.expires_at:
                if (
                    isinstance(existing, IntakePreview)
                    and existing.target == preview.target
                    and existing.instruction_digest == preview.instruction_digest
                    and existing.profile_name == preview.profile_name
                    and existing.goal_id == preview.goal_id
                    and existing.options_digest == preview.options_digest
                ):
                    return existing
                raise IntakeStateError("pending_intake_exists")
            if existing is not None:
                self._append({"event": "preview_expired", "user_id": user_id, "chat_id": chat_id, "ts": now})
                self._pending.pop(preview.key, None)
                self._scope_pending.pop(preview.key, None)
            self._append({"event": "preview_created", "preview": preview.as_event()})
            self._pending[preview.key] = preview
        return preview

    def create_scope_preview(
        self,
        *,
        document: Dict[str, Any],
        summary: Dict[str, Any],
        instruction: str,
        source: str,
        user_id: str,
        chat_id: str,
        message_id: str,
    ) -> ScopeIntakePreview:
        """Build the one pending **authorisation-document** preview for this (user, chat).

        ``summary`` 由调用方派生(它是唯一能 import 解析器的那一层,``core/`` 不能
        import ``agents/``)。这里只负责把它钉进 digest —— 操作员确认的是他当时看到的
        那组数字,不是一个可以事后重算的东西。
        """
        if not isinstance(document, dict) or not document:
            raise IntakeStateError("scope_document_required")
        summary = dict(summary or {})
        now = float(self._now())
        document_digest = canonical_digest(document)
        scope_digest = canonical_digest({
            "allowed_hosts": [str(host) for host in (summary.get("hosts") or ())],
            "forbidden_hosts": [str(host) for host in (summary.get("forbidden_hosts") or ())],
        })
        options_digest = canonical_digest({key: summary.get(key) for key in _SCOPE_OPTION_KEYS})
        instruction_digest = hashlib.sha256(instruction.encode("utf-8")).hexdigest()
        base = {
            "schema": "ScopeIntakePreview/v1",
            "intake_id": f"I-{uuid.uuid4().hex[:12]}",
            "source": source,
            "document": document,
            "document_digest": document_digest,
            "summary": summary,
            "instruction_digest": instruction_digest,
            "scope_digest": scope_digest,
            "options_digest": options_digest,
            "created_at": now,
            "expires_at": now + self.ttl_seconds,
        }
        preview = ScopeIntakePreview(
            intake_id=str(base["intake_id"]),
            user_id=user_id,
            chat_id=chat_id,
            message_id=message_id,
            source=source,
            document=document,
            document_digest=document_digest,
            summary=summary,
            instruction=instruction,
            instruction_digest=instruction_digest,
            created_at=now,
            expires_at=now + self.ttl_seconds,
            scope_digest=scope_digest,
            options_digest=options_digest,
            preview_digest=canonical_digest(base),
        )
        with self._lock():
            self._reload()
            existing = self._pending.get(preview.key) or self._scope_pending.get(preview.key)
            if existing is not None and now < existing.expires_at:
                if (
                    isinstance(existing, ScopeIntakePreview)
                    and existing.document_digest == document_digest
                    and existing.instruction_digest == instruction_digest
                ):
                    return existing
                raise IntakeStateError("pending_intake_exists")
            if existing is not None:
                self._append({"event": "preview_expired", "user_id": user_id, "chat_id": chat_id, "ts": now})
                self._pending.pop(preview.key, None)
                self._scope_pending.pop(preview.key, None)
            self._append({"event": "scope_preview_created", "preview": preview.as_event()})
            self._scope_pending[preview.key] = preview
        return preview

    def scope_pending(self, *, user_id: str, chat_id: str) -> Optional[ScopeIntakePreview]:
        with self._lock():
            self._reload()
            preview = self._scope_pending.get((user_id, chat_id))
            if preview is None:
                return None
            if float(self._now()) >= preview.expires_at:
                self._append({"event": "preview_expired", "user_id": user_id, "chat_id": chat_id, "ts": float(self._now())})
                self._scope_pending.pop((user_id, chat_id), None)
                return None
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

    def discard_pending(self, *, user_id: str, chat_id: str) -> bool:
        """Drop this (user, chat)'s pending preview without confirming it.

        Answers "one pending preview per chat" without making a typo permanent: a
        caller that has one pending and needs to submit a different target expires
        it first.  Recorded as the same ``preview_expired`` event the TTL path
        writes, so every reader sees one way for a preview to go away.
        """
        with self._lock():
            self._reload()
            key = (user_id, chat_id)
            # 一个槽:两种 preview 谁在都算"有东西待确认",丢弃就一起丢。
            had_target = self._pending.pop(key, None) is not None
            had_scope = self._scope_pending.pop(key, None) is not None
            if not (had_target or had_scope):
                return False
            self._append({"event": "preview_expired", "user_id": user_id, "chat_id": chat_id,
                          "ts": float(self._now())})
            return True

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

    def consume_scope_confirmation(
        self,
        *,
        user_id: str,
        chat_id: str,
        message_id: str,
        intake_id: str,
        options_digest: str,
        authorization: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Consume the pending document preview, binding it to the record minted from it.

        ``authorization`` 是调用方从**确认时手上那份原文**铸出来的授权记录。这里把
        它的 digest 一起写进回执,于是"回执里那份记录"和"当初看到的那份文档"之间
        多了一道可复核的链 —— 只看回执的人不必相信任何人转述。
        """
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
            preview = self._scope_pending.get((user_id, chat_id))
            if preview is None:
                raise IntakeStateError("no_pending_scope_intake_preview")
            if float(self._now()) >= preview.expires_at:
                self._append({"event": "preview_expired", "user_id": user_id, "chat_id": chat_id, "ts": float(self._now())})
                self._scope_pending.pop(preview.key, None)
                raise IntakeStateError("intake_preview_expired")
            if intake_id != preview.intake_id or options_digest != preview.options_digest:
                raise IntakeStateError("intake_confirmation_binding_mismatch")
            result = {
                "state": "confirmed",
                "intake_id": preview.intake_id,
                "authorization": authorization,
                "authorization_digest": canonical_digest(authorization),
                "authorization_id": str(authorization.get("authorization_id", "")),
                "program": str(preview.summary.get("program") or ""),
                # ``target`` 沿用这个字段名:对话卡片按同一个字段渲染两种 intake。
                "target": str(preview.summary.get("program") or preview.source or "scope document"),
                "instruction": preview.instruction,
                "instruction_digest": preview.instruction_digest,
                "document_digest": preview.document_digest,
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
            self._scope_pending.pop(preview.key, None)
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
    def _read_card(path: Path) -> Dict[str, Any]:
        """Parse and schema-check one stored card; no opinion about digests."""
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
            return TargetCardStore._validate_target_card(existing)
        except IntakeStateError as exc:
            raise IntakeStateError("canonical_target_card_mismatch") from exc

    @staticmethod
    def _read_existing(path: Path, *, expected_digest: str, target_id: str, relative_ref: str) -> Dict[str, Any]:
        existing_card = TargetCardStore._read_card(path)
        if canonical_digest(existing_card) != expected_digest:
            raise IntakeStateError("canonical_target_card_mismatch")
        return {
            "target_card": existing_card,
            "target_card_digest": expected_digest,
            "target_id": target_id,
            "target_card_ref": relative_ref,
        }

    def load(self, target_id: str, *, expected_digest: str = "") -> Dict[str, Any]:
        """Resolve the stored card for ``target_id`` — how a run finds its scope.

        ``expected_digest`` is the digest the caller confirmed.  A card that no
        longer matches it is a **mismatch, not a newer version**: whoever re-reads
        a card here is about to act on it, so drift has to fail.
        """
        relative_ref = _target_card_ref(target_id)
        card = self._read_card(self.project_root / relative_ref)
        digest = canonical_digest(card)
        if expected_digest and digest != expected_digest:
            raise IntakeStateError("canonical_target_card_mismatch")
        return {
            "target_card": card,
            "target_card_digest": digest,
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
