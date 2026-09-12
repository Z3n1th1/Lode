"""Quarantine-bound synthetic ToolRunner; real backends remain capability-gated."""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence

from runner_contract import RunnerBlockedError
from sandbox_store import SandboxRunStore, SandboxStoreError
from quarantine_importer import (
    QuarantineImportError,
    QuarantineImporter,
    absolute_lexical,
    ensure_existing_safe_directory,
)


RUN_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,94}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
MAX_SCOPE_BYTES = 64 * 1024
MAX_CARD_BYTES = 64 * 1024
MAX_COMMAND_ITEMS = 64
MAX_COMMAND_BYTES = 16 * 1024
SYNTHETIC_BLOCKED_EXIT_CODE = 125


class ToolRunnerError(RuntimeError):
    """The ToolRunner refused a run before any external tool was reached."""


@dataclass(frozen=True)
class ToolRunSpec:
    task_id: str
    run_id: str
    scope_sha256: str
    command_sha256: str
    tool_sha256: str
    wall_seconds: int


def _canonical_digest(value: Mapping[str, Any]) -> str:
    text = json.dumps(dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _default_identity() -> int:
    getter = getattr(os, "geteuid", None)
    if getter is None:
        raise ToolRunnerError("tool_runner_identity_unavailable")
    return int(getter())


class SyntheticToolRunner:
    """Write a verified no-execution card through the five-argument runner seam.

    This class is intentionally not a test executor. It revalidates the inspected
    source and returns a stable blocked outcome; a real backend must be a separate,
    capability-verified rootless implementation.
    """

    def __init__(
        self,
        *,
        quarantine_importer: QuarantineImporter,
        source_path: Path | str,
        quarantine_receipt: Mapping[str, Any],
        runs_root: Path | str,
        identity_provider=_default_identity,
    ) -> None:
        if not isinstance(quarantine_importer, QuarantineImporter):
            raise TypeError("quarantine_importer_required")
        if not isinstance(quarantine_receipt, Mapping):
            raise TypeError("quarantine_receipt_required")
        self._importer = quarantine_importer
        try:
            self._source_path = self._importer.canonical_source_path(source_path)
            self._receipt = self._importer.validate_receipt(quarantine_receipt)
        except QuarantineImportError as exc:
            raise ToolRunnerError("tool_quarantine_receipt_invalid") from exc
        self._runs_root = absolute_lexical(runs_root)
        self._identity_provider = identity_provider

    @staticmethod
    def _load_scope(scope_bytes: bytes) -> tuple[str, str, str]:
        try:
            scope = json.loads(scope_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ToolRunnerError("tool_runner_scope_invalid") from exc
        if not isinstance(scope, dict):
            raise ToolRunnerError("tool_runner_scope_invalid")
        task_id = scope.get("task_id")
        run_id = scope.get("run_id")
        if (
            not isinstance(task_id, str)
            or re.fullmatch(r"T-\d+", task_id) is None
            or not isinstance(run_id, str)
            or RUN_ID_RE.fullmatch(run_id) is None
        ):
            raise ToolRunnerError("tool_runner_scope_invalid")
        return task_id, run_id, hashlib.sha256(scope_bytes).hexdigest()

    def _validate_task_dir(self, cwd: Path | str) -> Path:
        try:
            runs_root = ensure_existing_safe_directory(self._runs_root, "tool_runner_runs_root")
        except QuarantineImportError as exc:
            raise ToolRunnerError("tool_runner_runs_root_invalid") from exc
        task_dir = absolute_lexical(cwd)
        try:
            relative = task_dir.relative_to(runs_root)
        except ValueError as exc:
            raise ToolRunnerError("tool_runner_task_dir_outside_runs_root") from exc
        if len(relative.parts) != 1 or re.fullmatch(r"T-\d+", relative.name) is None:
            raise ToolRunnerError("tool_runner_task_dir_invalid")
        try:
            return ensure_existing_safe_directory(task_dir, "tool_runner_task_dir")
        except QuarantineImportError as exc:
            raise ToolRunnerError("tool_runner_task_dir_invalid") from exc

    def _validate_command(self, command: Sequence[str]) -> tuple[tuple[str, ...], str]:
        if isinstance(command, (str, bytes)) or not isinstance(command, Sequence):
            raise ToolRunnerError("tool_runner_command_invalid")
        items = tuple(command)
        if (
            not items
            or len(items) > MAX_COMMAND_ITEMS
            or any(not isinstance(item, str) or not item or "\x00" in item for item in items)
        ):
            raise ToolRunnerError("tool_runner_command_invalid")
        encoded = json.dumps(items, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(encoded) > MAX_COMMAND_BYTES:
            raise ToolRunnerError("tool_runner_command_invalid")
        if absolute_lexical(items[0]) != self._source_path:
            raise ToolRunnerError("tool_runner_command_source_mismatch")
        return items, hashlib.sha256(encoded).hexdigest()

    def _reverify_source(self) -> Dict[str, Any]:
        try:
            return self._importer.verify_receipt(self._source_path, self._receipt)
        except QuarantineImportError as exc:
            if str(exc) == "quarantine_source_changed":
                raise ToolRunnerError("tool_quarantine_source_changed") from exc
            raise ToolRunnerError("tool_quarantine_source_invalid") from exc

    @staticmethod
    def _blocked_card(spec: ToolRunSpec, receipt: Mapping[str, Any]) -> Dict[str, Any]:
        card: Dict[str, Any] = {
            "schema": "SandboxRunCard/v1",
            "execution_mode": "synthetic",
            "status": "blocked",
            "block_reason": "synthetic_no_execution",
            "exit_code": SYNTHETIC_BLOCKED_EXIT_CODE,
            "task_id": spec.task_id,
            "run_id": spec.run_id,
            "scope_sha256": spec.scope_sha256,
            "command_sha256": spec.command_sha256,
            "tool_sha256": spec.tool_sha256,
            "quarantine_receipt_sha256": receipt["receipt_sha256"],
            "backend": "synthetic",
            "rootless": False,
            "network": "none",
            "limits": {
                "wall_seconds": spec.wall_seconds,
                "memory_bytes": 128 * 1024 * 1024,
                "pids": 32,
            },
            "output": {"state": "synthetic_no_output", "bytes": 0},
            "cleanup": {"state": "not_required"},
            "secret_exposed": False,
        }
        card["card_sha256"] = _canonical_digest(card)
        return card

    @classmethod
    def _validate_card(cls, raw: Mapping[str, Any], expected: Mapping[str, Any]) -> None:
        candidate = dict(raw)
        if set(candidate) != set(expected) or candidate.get("card_sha256") != _canonical_digest(
            {key: value for key, value in candidate.items() if key != "card_sha256"}
        ):
            raise ToolRunnerError("sandbox_run_card_invalid")
        if not cls._strict_equal(candidate, dict(expected)):
            raise ToolRunnerError("sandbox_run_card_invalid")

    @classmethod
    def _strict_equal(cls, actual: Any, expected: Any) -> bool:
        if type(actual) is not type(expected):
            return False
        if isinstance(expected, dict):
            return set(actual) == set(expected) and all(
                cls._strict_equal(actual[key], expected[key]) for key in expected
            )
        if isinstance(expected, list):
            return len(actual) == len(expected) and all(
                cls._strict_equal(left, right) for left, right in zip(actual, expected)
            )
        return actual == expected

    @staticmethod
    def _load_card_json(raw_bytes: bytes) -> Dict[str, Any]:
        def no_duplicate_keys(pairs):
            result: Dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate_json_key")
                result[key] = value
            return result

        try:
            raw = json.loads(raw_bytes.decode("utf-8"), object_pairs_hook=no_duplicate_keys)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ToolRunnerError("sandbox_run_card_invalid") from exc
        if not isinstance(raw, dict):
            raise ToolRunnerError("sandbox_run_card_invalid")
        return raw

    @classmethod
    def _read_card(cls, raw_bytes: bytes, expected: Mapping[str, Any]) -> None:
        raw = cls._load_card_json(raw_bytes)
        cls._validate_card(raw, expected)

    def __call__(
        self,
        command: Sequence[str],
        cwd: Path,
        env: Mapping[str, str],
        log_path: Path,
        timeout: int,
    ) -> int:
        del env, log_path
        try:
            uid = int(self._identity_provider())
        except ToolRunnerError:
            raise
        except Exception as exc:
            raise ToolRunnerError("tool_runner_identity_unavailable") from exc
        if uid == 0:
            raise ToolRunnerError("tool_runner_root_forbidden")
        if uid < 0:
            raise ToolRunnerError("tool_runner_identity_unavailable")
        if type(timeout) is not int or not 1 <= timeout <= 3600:
            raise ToolRunnerError("tool_runner_timeout_invalid")

        task_dir = self._validate_task_dir(cwd)
        _, command_sha256 = self._validate_command(command)
        try:
            with SandboxRunStore(self._runs_root, task_dir) as store:
                task_id, run_id, _ = self._load_scope(store.read_scope_bytes(max_bytes=MAX_SCOPE_BYTES))
                receipt = self._reverify_source()
                store.prepare_run(run_id)
                self._validate_task_dir(task_dir)
                locked_task_id, locked_run_id, scope_sha256 = self._load_scope(
                    store.read_scope_bytes(max_bytes=MAX_SCOPE_BYTES)
                )
                if (locked_task_id, locked_run_id) != (task_id, run_id):
                    raise ToolRunnerError("tool_runner_scope_changed")
                receipt = self._reverify_source()
                spec = ToolRunSpec(
                    task_id=locked_task_id,
                    run_id=locked_run_id,
                    scope_sha256=scope_sha256,
                    command_sha256=command_sha256,
                    tool_sha256=str(receipt["source_sha256"]),
                    wall_seconds=timeout,
                )
                expected_card = self._blocked_card(spec, receipt)
                if store.card_exists():
                    self._read_card(store.read_card_bytes(max_bytes=MAX_CARD_BYTES), expected_card)
                    raise RunnerBlockedError("synthetic_no_execution")
                payload = json.dumps(expected_card, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n"
                try:
                    store.publish_card_once(payload)
                except FileExistsError:
                    self._read_card(store.read_card_bytes(max_bytes=MAX_CARD_BYTES), expected_card)
                    raise RunnerBlockedError("synthetic_no_execution")
                self._read_card(store.read_card_bytes(max_bytes=MAX_CARD_BYTES), expected_card)
                final_task_id, final_run_id, final_scope_sha256 = self._load_scope(
                    store.read_scope_bytes(max_bytes=MAX_SCOPE_BYTES)
                )
                if (final_task_id, final_run_id, final_scope_sha256) != (locked_task_id, locked_run_id, scope_sha256):
                    raise ToolRunnerError("tool_runner_scope_changed")
                raise RunnerBlockedError("synthetic_no_execution")
        except (SandboxStoreError, OSError) as exc:
            raise ToolRunnerError("tool_runner_quarantine_path_invalid") from exc
