#!/usr/bin/env python3
"""Durable Strix task adapter reused from the acceptance worktree.

The adapter is deliberately narrow: it creates one bounded, auditable task and
persists an idempotency key before the background runner starts.  It does not
choose a target, bypass policy, or send raw reports to Feishu.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


_CORE_DIR = Path(__file__).resolve().parents[1] / "core"
if str(_CORE_DIR) not in sys.path:
    sys.path.insert(0, str(_CORE_DIR))

from file_lock import AdvisoryFileLock
from runner_contract import RunnerBlockedError


TASK_KEYWORDS = ("测试", "扫", "挖", "审计")
URL_RE = re.compile(r"https?://[^\s\"'<>）)】\]]+", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}"
    r"(?::\d{1,5})?(?:/[^\s\"'<>）)】\]]*)?",
    re.IGNORECASE,
)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?:/[^\s\"'<>）)】\]]*)?")

SCOPE_SUFFIX = (
    "【范围约束】仅对上述目标做被动侦察与只读低频验证；"
    "禁止主动攻击、爆破、批量 fuzz、任何状态变更/写操作；"
    "超出该目标域名/IP 的资产一律不碰。"
)
DEFAULT_STRIX_BIN = "/opt/pentest-agent/venv-strix/bin/strix"
TASK_TIMEOUT_SEC = int(os.environ.get("STRIX_TASK_TIMEOUT", "3600"))
DEFAULT_PROGRESS_INTERVAL_SECONDS = 30 * 60
RUNNER_BLOCKED_EXIT_CODE = 125


class BusyError(RuntimeError):
    """A different task is already running under the single-task policy."""


class TaskRecoveryRequired(BusyError):
    """A prior task needs explicit operator resolution before work can continue."""


def extract_target(text: str) -> Optional[str]:
    """Extract the first URL, IP, or domain in textual order."""
    matches = []
    for precedence, pattern in enumerate((URL_RE, IP_RE, DOMAIN_RE)):
        match = pattern.search(text or "")
        if match:
            matches.append((match.start(), precedence, match.group(0)))
    if not matches:
        return None
    return min(matches)[2].rstrip(".,;，。；）)】]")


def classify(text: str, *, force: bool = False) -> Optional[Tuple[str, str]]:
    """Return ``(target, instruction)`` when the text should create a task."""
    instruction = (text or "").strip()
    target = extract_target(instruction)
    if not instruction or not target:
        return None
    if not force and not any(keyword in instruction for keyword in TASK_KEYWORDS):
        return None
    return target, instruction


def _default_runner(
    command: List[str],
    cwd: Path,
    env: Dict[str, str],
    log_path: Path,
    timeout: int,
) -> int:
    """Fail closed until a capability-verified ToolRunner is injected."""
    del command, cwd, env, log_path, timeout
    raise RunnerBlockedError("external_tool_runner_unconfigured")


class TaskManager:
    """Submit one Strix task with durable, cross-restart idempotency.

    ``idempotency_key`` is mandatory and must identify exactly one immutable goal
    request.  A replay returns the prior task record rather than executing Strix
    again, including when a previous consumer crashed after a successful submit.
    """

    def __init__(
        self,
        tasks_file: Path,
        runs_dir: Path,
        *,
        strix_bin: str = DEFAULT_STRIX_BIN,
        notify_fn: Optional[Callable[[str, str], None]] = None,
        event_fn: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        runner: Optional[Callable[..., int]] = None,
        scan_mode: str = "quick",
        timeout: int = TASK_TIMEOUT_SEC,
        progress_interval: float = DEFAULT_PROGRESS_INTERVAL_SECONDS,
    ) -> None:
        if progress_interval <= 0:
            raise ValueError("progress_interval_must_be_positive")
        self.tasks_file = Path(tasks_file)
        self.runs_dir = Path(runs_dir)
        self.strix_bin = strix_bin
        self.notify_fn = notify_fn
        self.event_fn = event_fn
        self.runner = runner or _default_runner
        self.scan_mode = scan_mode
        self.timeout = timeout
        self.progress_interval = float(progress_interval)
        self._lock = threading.Lock()
        self._running: Optional[str] = None
        self._lock_path = self.tasks_file.with_name(self.tasks_file.name + ".lock")
        self._event_lock = threading.Lock()
        self._pending_events: List[Tuple[str, Dict[str, Any]]] = []
        self._event_dispatcher_running = False

    def _file_lock(self) -> AdvisoryFileLock:
        return AdvisoryFileLock(self._lock_path)

    def _append_unlocked(self, entry: Dict[str, Any]) -> None:
        self.tasks_file.parent.mkdir(parents=True, exist_ok=True)
        with self.tasks_file.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")

    def _latest_unlocked(self) -> Dict[str, Dict[str, Any]]:
        latest: Dict[str, Dict[str, Any]] = {}
        if not self.tasks_file.is_file():
            return latest
        for raw_line in self.tasks_file.read_text(encoding="utf-8").splitlines():
            try:
                event = json.loads(raw_line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict) or not event.get("id"):
                continue
            task_id = str(event["id"])
            latest[task_id] = {**latest.get(task_id, {}), **event}
        return latest

    @staticmethod
    def _next_id(latest: Dict[str, Dict[str, Any]]) -> str:
        sequence = 0
        for task_id in latest:
            match = re.fullmatch(r"T-(\d+)", task_id)
            if match:
                sequence = max(sequence, int(match.group(1)))
        return f"T-{sequence + 1:03d}"

    @staticmethod
    def _validate_replay(
        task: Dict[str, Any],
        *,
        target: str,
        instruction: str,
        goal_id: str,
        profile_name: str,
        target_id: str,
        target_card_digest: str,
    ) -> None:
        immutable = {
            "target": target,
            "instruction": instruction,
            "goal_id": goal_id,
            "profile_name": profile_name,
            "target_id": target_id,
            "target_card_digest": target_card_digest,
        }
        if any(task.get(field, "") != value for field, value in immutable.items()):
            raise ValueError(f"idempotency_key_conflict:{task.get('idempotency_key', '')}")

    @staticmethod
    def _find_by_idempotency(
        latest: Dict[str, Dict[str, Any]],
        idempotency_key: str,
    ) -> Optional[Dict[str, Any]]:
        for task in latest.values():
            if task.get("idempotency_key") == idempotency_key:
                return dict(task)
        return None

    @staticmethod
    def _owner_is_alive(owner_pid: Any) -> bool:
        try:
            pid = int(owner_pid)
        except (TypeError, ValueError):
            return False
        if pid <= 0:
            return False
        # Windows does not support POSIX-style signal 0 probing reliably; never
        # invoke os.kill against the current process merely to verify ownership.
        if pid == os.getpid():
            return True
        if os.name == "nt":
            return TaskManager._windows_owner_is_alive(pid)
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError:
            return False
        return True

    @staticmethod
    def _windows_owner_is_alive(pid: int) -> bool:
        """Probe another Windows process without sending it a signal."""
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.GetExitCodeProcess.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
        kernel32.GetExitCodeProcess.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel32.CloseHandle.restype = wintypes.BOOL

        process = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not process:
            return ctypes.get_last_error() == 5  # ERROR_ACCESS_DENIED: conservatively treat as live.
        try:
            exit_code = wintypes.DWORD()
            if not kernel32.GetExitCodeProcess(process, ctypes.byref(exit_code)):
                return False
            return exit_code.value == 259  # STILL_ACTIVE
        finally:
            kernel32.CloseHandle(process)

    def _task_dir(self, task_id: str) -> Path:
        if re.fullmatch(r"T-\d+", task_id) is None:
            raise ValueError(f"invalid_task_id:{task_id}")
        return self.runs_dir / task_id

    def _finalization_error_path(self, task_id: str) -> Path:
        return self._task_dir(task_id) / "finalization_error.json"

    def _promote_recovery_pending_unlocked(self, latest: Dict[str, Dict[str, Any]]) -> None:
        for task_id, task in list(latest.items()):
            if task.get("status") != "running":
                continue
            try:
                finalization_error = self._finalization_error_path(task_id).is_file()
            except ValueError:
                finalization_error = False
            if not finalization_error and self._owner_is_alive(task.get("owner_pid")):
                continue
            event = {
                "event": "recovery_pending",
                "id": task_id,
                "status": "recovery_pending",
                "recovery_reason": "finalization_write_failed" if finalization_error else "owner_not_alive",
                "recovery_ts": time.time(),
            }
            self._append_unlocked(event)
            latest[task_id] = {**task, **event}

    @staticmethod
    def _active_task(latest: Dict[str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        return next(
            (
                task
                for task in latest.values()
                if task.get("status") in {"running", "recovery_pending"}
            ),
            None,
        )

    @staticmethod
    def _scope_document(task: Dict[str, Any]) -> Dict[str, Any]:
        """Derive the sidecar from immutable task-ledger fields."""
        task_id = str(task["id"])
        instruction = str(task["instruction"])
        return {
            "task_id": task_id,
            "goal_id": task["goal_id"],
            "profile_name": task["profile_name"],
            "idempotency_key": task["idempotency_key"],
            "target": task["target"],
            "target_id": task.get("target_id", ""),
            "target_card_digest": task.get("target_card_digest", ""),
            "instruction_raw": instruction,
            "instruction_final": f"{instruction}\n{SCOPE_SUFFIX}",
            "policy": "passive_recon_only",
            "scan_mode": task["scan_mode"],
            "timeout_seconds": task["timeout_seconds"],
            "user_id": task.get("user_id", ""),
            "chat_id": task.get("chat_id", ""),
            "created_ts": task["created_ts"],
            "run_id": task["run_id"],
        }

    @staticmethod
    def _scope_bytes(task: Dict[str, Any]) -> bytes:
        return json.dumps(
            TaskManager._scope_document(task), ensure_ascii=False, indent=2, sort_keys=True
        ).encode("utf-8")

    @staticmethod
    def _scope_sha256(task: Dict[str, Any]) -> str:
        return hashlib.sha256(TaskManager._scope_bytes(task)).hexdigest()

    def _write_scope(self, task: Dict[str, Any]) -> None:
        task_id = str(task["id"])
        task_dir = self._task_dir(task_id)
        task_dir.mkdir(parents=True, exist_ok=True)
        scope_path = task_dir / "scope.json"
        scope_bytes = self._scope_bytes(task)
        expected_scope_sha256 = self._scope_sha256(task)
        if str(task.get("scope_sha256", "")) != expected_scope_sha256:
            raise ValueError("task_scope_binding_invalid")
        scope_path.write_bytes(scope_bytes)
        evidence_root = task_dir / "evidence"
        evidence_root.mkdir(exist_ok=True)
        target_id = str(task.get("target_id", ""))
        target_card_digest = str(task.get("target_card_digest", ""))
        binding: Dict[str, Any] = {
            "schema": "TaskEvidenceBinding/v2" if target_id or target_card_digest else "TaskEvidenceBinding/v1",
            "task_id": task_id,
            "target": task["target"],
            "scope_sha256": expected_scope_sha256,
            "run_id": task["run_id"],
        }
        if target_id or target_card_digest:
            binding["target_id"] = target_id
            binding["target_card_digest"] = target_card_digest
        (evidence_root / "task_binding.json").write_text(
            json.dumps(binding, ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    def _activate_reservation_unlocked(self, reservation: Dict[str, Any]) -> Dict[str, Any]:
        task_id = str(reservation["id"])
        created = {
            **reservation,
            "event": "created",
            "status": "running",
            "created_ts": time.time(),
            "run_id": str(reservation.get("run_id") or f"run-{uuid.uuid4().hex}"),
            "owner_pid": os.getpid(),
            "scan_mode": reservation.get("scan_mode", self.scan_mode),
            "timeout_seconds": reservation.get("timeout_seconds", self.timeout),
            "output_path": str(self._task_dir(task_id)),
        }
        created["scope_sha256"] = self._scope_sha256(created)
        self._write_scope(created)
        self._append_unlocked(created)
        return created

    def resolve_recovery(self, task_id: str, *, operator_note: str) -> Dict[str, Any]:
        """Record an explicit decision not to resume an uncertain prior task."""
        task_id = task_id.strip()
        operator_note = operator_note.strip()
        if not operator_note:
            raise ValueError("operator_note_required")
        with self._lock:
            with self._file_lock():
                latest = self._latest_unlocked()
                self._promote_recovery_pending_unlocked(latest)
                task = latest.get(task_id)
                if task is None:
                    raise KeyError(f"unknown_task:{task_id}")
                if task.get("status") != "recovery_pending":
                    raise ValueError(f"task_not_recovery_pending:{task_id}")
                event = {
                    "event": "recovery_resolved",
                    "id": task_id,
                    "status": "interrupted",
                    "recovery_action": "mark_interrupted",
                    "operator_note": operator_note,
                    "recovered_ts": time.time(),
                }
                self._append_unlocked(event)
                return {**task, **event}

    def list_tasks(self, limit: int = 10) -> List[Dict[str, Any]]:
        with self._file_lock():
            latest = self._latest_unlocked()
            self._promote_recovery_pending_unlocked(latest)
        tasks = sorted(latest.values(), key=lambda task: task.get("created_ts", 0), reverse=True)
        return tasks[:limit]

    @staticmethod
    def _task_owned_evidence_dir(task_dir: Path, evidence_dir: Path) -> Path:
        root = (task_dir / "evidence").resolve()
        try:
            resolved = Path(evidence_dir).resolve(strict=True)
        except OSError as exc:
            raise ValueError("evidence_dir_unavailable") from exc
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise ValueError("evidence_dir_outside_task") from exc
        if not resolved.is_dir():
            raise ValueError("evidence_dir_not_directory")
        return resolved

    @staticmethod
    def _validate_task_evidence_binding(task: Dict[str, Any], task_dir: Path) -> Dict[str, Any]:
        scope_path = task_dir / "scope.json"
        binding_path = task_dir / "evidence" / "task_binding.json"
        try:
            if scope_path.stat().st_size > 64 * 1024 or binding_path.stat().st_size > 16 * 1024:
                raise ValueError("task_evidence_binding_invalid")
            scope_bytes = scope_path.read_bytes()
            scope = json.loads(scope_bytes.decode("utf-8"))
            binding = json.loads(binding_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ValueError("task_evidence_binding_invalid") from exc
        if not isinstance(scope, dict) or not isinstance(binding, dict):
            raise ValueError("task_evidence_binding_invalid")
        target_id = str(task.get("target_id", ""))
        target_card_digest = str(task.get("target_card_digest", ""))
        target_bound = bool(target_id or target_card_digest)
        if target_bound and (not target_id or not target_card_digest):
            raise ValueError("task_evidence_binding_invalid")
        expected_keys = (
            {"schema", "task_id", "target", "target_id", "target_card_digest", "scope_sha256", "run_id"}
            if target_bound
            else {"schema", "task_id", "target", "scope_sha256", "run_id"}
        )
        if set(binding) != expected_keys:
            raise ValueError("task_evidence_binding_invalid")
        task_id = binding.get("task_id")
        target = binding.get("target")
        scope_sha256 = binding.get("scope_sha256")
        run_id = binding.get("run_id")
        if (
            binding.get("schema") != ("TaskEvidenceBinding/v2" if target_bound else "TaskEvidenceBinding/v1")
            or not isinstance(task_id, str)
            or re.fullmatch(r"T-\d+", task_id) is None
            or task_id != task.get("id")
            or not isinstance(target, str)
            or not 1 <= len(target) <= 2048
            or target != task.get("target")
            or not isinstance(run_id, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,94}", run_id) is None
            or run_id != task.get("run_id")
            or not isinstance(scope_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", scope_sha256) is None
            or scope_sha256 != hashlib.sha256(scope_bytes).hexdigest()
        ):
            raise ValueError("task_evidence_binding_invalid")
        ledger_scope_sha256 = str(task.get("scope_sha256", ""))
        if ledger_scope_sha256:
            if (
                re.fullmatch(r"[0-9a-f]{64}", ledger_scope_sha256) is None
                or ledger_scope_sha256 != scope_sha256
            ):
                raise ValueError("task_evidence_binding_invalid")
        if target_bound and (
            not isinstance(binding.get("target_id"), str)
            or binding["target_id"] != target_id
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", target_id) is None
            or not isinstance(binding.get("target_card_digest"), str)
            or binding["target_card_digest"] != target_card_digest
            or re.fullmatch(r"[0-9a-f]{64}", target_card_digest) is None
        ):
            raise ValueError("task_evidence_binding_invalid")
        return binding

    @staticmethod
    def _task_resolution_snapshot(task: Dict[str, Any], task_dir: Path) -> Dict[str, str]:
        """Return the immutable task fields a verifier result is allowed to bind."""
        return {
            "id": str(task.get("id", "")),
            "goal_id": str(task.get("goal_id", "")),
            "target": str(task.get("target", "")),
            "target_id": str(task.get("target_id", "")),
            "target_card_digest": str(task.get("target_card_digest", "")),
            "scope_sha256": str(task.get("scope_sha256", "")),
            "run_id": str(task.get("run_id", "")),
            "output_path": str(task_dir),
        }

    @staticmethod
    def _task_binding_digest(binding: Dict[str, Any]) -> str:
        canonical = json.dumps(binding, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def _validate_canonical_pair_identity(
        task: Dict[str, Any], verifier: Dict[str, Any], pairs: Any
    ) -> None:
        """Require every canonical pair to match a TargetCard-bound task."""
        target_card_digest = str(task.get("target_card_digest", ""))
        if not target_card_digest:
            return
        target_id = str(task.get("target_id", ""))
        pair_ids = verifier.get("evidence_pair_ids")
        if not target_id or not isinstance(pair_ids, list) or not isinstance(pairs, dict):
            raise ValueError("canonical_target_pair_provenance_missing")
        for pair_id in pair_ids:
            pair = pairs.get(pair_id)
            if not isinstance(pair, dict):
                raise ValueError("canonical_target_pair_provenance_missing")
            if str(pair.get("target_id", "")) != target_id:
                raise ValueError("canonical_target_pair_identity_mismatch")
            if str(pair.get("target_card_digest", "")).lower() != target_card_digest:
                raise ValueError("canonical_target_pair_digest_mismatch")

    @staticmethod
    def _canonical_evidence_lock(evidence_dir: Path):
        """Reuse the canonical writer lock around verifier validation and publish."""
        guardrails_root = Path(__file__).resolve().parents[1] / "guardrails-mcp"
        if str(guardrails_root) not in sys.path:
            sys.path.insert(0, str(guardrails_root))
        try:
            from guardrails import scripts_bridge  # type: ignore

            if not scripts_bridge.scripts_available():
                return AdvisoryFileLock(evidence_dir / ".task-router-finding.lock")
            import evidence_indexer  # type: ignore
        except Exception as exc:
            raise RuntimeError("canonical_evidence_lock_unavailable") from exc
        return evidence_indexer.finding_write_lock(evidence_dir)

    @staticmethod
    def _verified_finding_fields(
        finding: Dict[str, Any],
        verifier: Dict[str, Any],
        *,
        task_target_id: str = "",
        task_target_card_digest: str = "",
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        if verifier.get("schema") != "VerifierResult/v1":
            raise ValueError("verifier_schema_invalid")
        if verifier.get("status") != "confirmed" or verifier.get("recommend_report") is not True:
            raise ValueError("verifier_status_not_confirmed")
        verification_mode = str(verifier.get("verification_mode", "")).strip()
        if verification_mode not in {"human", "independent_agent"}:
            raise ValueError("verifier_mode_not_independent")
        verification_origin = str(verifier.get("verification_origin", "")).strip()
        allowed_origins = {
            "independent_agent": {"separate_agent", "external_import"},
            "human": {"human_operator", "external_import"},
        }
        if verification_origin not in allowed_origins[verification_mode]:
            raise ValueError("verifier_origin_invalid")
        verifier_id = str(verifier.get("verifier_id", "")).strip()
        if not verifier_id or (verification_mode == "independent_agent" and verifier_id == "verifier-local"):
            raise ValueError("verifier_identity_invalid")
        record_digest = str(verifier.get("record_digest", "")).strip().lower()
        if re.fullmatch(r"[0-9a-f]{64}", record_digest) is None:
            raise ValueError("verifier_record_digest_invalid")
        input_manifest_digest = str(verifier.get("input_manifest_digest", "")).strip().lower()
        if re.fullmatch(r"[0-9a-f]{64}", input_manifest_digest) is None:
            raise ValueError("verifier_input_manifest_digest_invalid")

        run_id = str(verifier.get("run_id", "")).strip()
        target_id = str(verifier.get("target_id", "")).strip()
        if not run_id or not target_id:
            raise ValueError("verifier_provenance_fields_invalid")
        if task_target_card_digest and target_id != task_target_id:
            raise ValueError("canonical_target_identity_mismatch")
        if verifier.get("integrity_status") != "pass":
            raise ValueError("verifier_integrity_not_pass")
        evidence_pair_ids = verifier.get("evidence_pair_ids")
        evidence_pair_count = verifier.get("evidence_pair_count")
        if (
            not isinstance(evidence_pair_ids, list)
            or type(evidence_pair_count) is not int
            or evidence_pair_count != len(evidence_pair_ids)
            or not evidence_pair_ids
            or any(not isinstance(pair_id, str) or not pair_id.strip() for pair_id in evidence_pair_ids)
            or len(set(evidence_pair_ids)) != len(evidence_pair_ids)
        ):
            raise ValueError("verifier_pair_provenance_invalid")
        evidence_pair_ids_digest = hashlib.sha256(
            json.dumps(evidence_pair_ids, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        impact_assertion_digest = str(verifier.get("impact_assertion_digest", "")).strip().lower()
        if re.fullmatch(r"[0-9a-f]{64}", impact_assertion_digest) is None:
            raise ValueError("verifier_impact_assertion_digest_invalid")
        worker_attestation_raw = verifier.get("worker_attestation_digest")
        worker_attestation_digest = (
            str(worker_attestation_raw).strip().lower()
            if worker_attestation_raw is not None
            else None
        )
        if worker_attestation_digest is not None and re.fullmatch(r"[0-9a-f]{64}", worker_attestation_digest) is None:
            raise ValueError("verifier_worker_attestation_digest_invalid")
        if verification_mode == "independent_agent" and worker_attestation_digest is None:
            raise ValueError("verifier_worker_attestation_digest_invalid")

        finding_id = str(finding.get("finding_id", "")).strip()
        if (
            re.fullmatch(r"[A-Za-z0-9_.:-]{1,120}", finding_id) is None
            or finding_id != str(verifier.get("finding_id", "")).strip()
        ):
            raise ValueError("verifier_finding_id_mismatch")
        title = str(finding.get("title", "")).strip()
        severity = str(finding.get("severity", "")).strip().lower()
        if not title or severity not in {"low", "medium", "high", "critical"}:
            raise ValueError("finding_fields_invalid")
        safe_finding = {
            "finding_id": finding_id[:120],
            "title": title[:240],
            "detail": str(finding.get("detail", "")).strip()[:360],
            "type": str(finding.get("type", "")).strip()[:120],
            "severity": severity,
            "evidence_level": str(finding.get("evidence_level", "")).strip()[:120],
            "verifier_status": "confirmed",
            "evidence_ref": f"VerifierResult:{record_digest[:12]}",
        }
        safe_verifier = {
            "schema": "TaskVerifierProvenance/v1",
            "source_schema": "VerifierResult/v1",
            "finding_id": finding_id[:120],
            "run_id": run_id[:95],
            "target_id": target_id[:160],
            "target_id_binding": "target_card" if task_target_card_digest else "unresolved_dependency",
            "target_card_digest": task_target_card_digest or None,
            "status": "confirmed",
            "recommend_report": True,
            "verification_mode": verification_mode,
            "verification_origin": verification_origin[:120],
            "verifier_id": verifier_id[:120],
            "integrity_status": "pass",
            "evidence_pair_count": evidence_pair_count,
            "evidence_pair_ids_digest": evidence_pair_ids_digest,
            "impact_assertion_digest": impact_assertion_digest,
            "worker_attestation_digest": worker_attestation_digest,
            "record_digest": record_digest,
            "input_manifest_digest": input_manifest_digest,
        }
        return safe_finding, safe_verifier

    @staticmethod
    def _resolve_canonical_verified_finding(task: Dict[str, Any], evidence_dir: Path) -> Dict[str, Any]:
        """Reuse canonical verifier validation instead of trusting caller-supplied claims."""
        task_output = str(task.get("output_path", "")).strip()
        if not task_output:
            raise ValueError("task_evidence_binding_invalid")
        task_dir = Path(task_output)
        binding = TaskManager._validate_task_evidence_binding(task, task_dir)
        guardrails_root = Path(__file__).resolve().parents[1] / "guardrails-mcp"
        if str(guardrails_root) not in sys.path:
            sys.path.insert(0, str(guardrails_root))
        try:
            from guardrails import scripts_bridge  # type: ignore

            if not scripts_bridge.scripts_available():
                raise RuntimeError("canonical_verifier_scripts_unavailable")
            import trust_chain  # type: ignore

            checked = trust_chain.validate_verifier_result(evidence_dir, require_confirmed=True)
        except Exception as exc:
            raise RuntimeError("canonical_verifier_validation_unavailable") from exc
        if not checked.get("ok") or not isinstance(checked.get("record"), dict):
            raise ValueError("canonical_verifier_rejected")
        verifier = dict(checked["record"])
        pairs = checked.get("pairs")
        if (
            verifier.get("run_id") != binding["run_id"]
            or verifier.get("input_manifest_digest") != checked.get("manifest", {}).get("digest")
        ):
            raise ValueError("canonical_task_binding_missing")
        finding_id = str(verifier.get("finding_id", "")).strip()
        if not finding_id:
            raise ValueError("canonical_verifier_finding_id_missing")
        TaskManager._validate_canonical_pair_identity(task, verifier, pairs)
        return {
            "finding": {
                "finding_id": finding_id,
                "title": "已确认安全问题",
                "detail": "",
                "type": "verified_finding",
                "severity": "medium",
                "evidence_level": "L4_independent_reproduction",
            },
            "verifier": verifier,
            "pairs": pairs,
        }

    def publish_verified_finding(
        self,
        task_id: str,
        evidence_dir: Path,
    ) -> Dict[str, Any]:
        """Publish a task-owned, canonical-verified finding exactly once."""
        task_id = task_id.strip()
        if re.fullmatch(r"T-\d+", task_id) is None:
            raise ValueError("invalid_task_id")

        with self._lock:
            with self._file_lock():
                latest = self._latest_unlocked()
                task = latest.get(task_id)
                if task is None:
                    raise KeyError(f"unknown_task:{task_id}")
                task = dict(task)
        task_dir = self._task_dir(task_id)
        owned_evidence_dir = self._task_owned_evidence_dir(task_dir, Path(evidence_dir))
        resolver_task = self._task_resolution_snapshot(task, task_dir)
        initial_binding = self._validate_task_evidence_binding(resolver_task, task_dir)
        with self._canonical_evidence_lock(owned_evidence_dir):
            resolved = self._resolve_canonical_verified_finding(resolver_task, owned_evidence_dir)
            if not isinstance(resolved, dict):
                raise ValueError("verifier_resolver_result_invalid")
            finding = resolved.get("finding")
            verifier = resolved.get("verifier")
            if not isinstance(finding, dict) or not isinstance(verifier, dict):
                raise ValueError("verifier_resolver_result_invalid")
            initial_finding, initial_verifier = self._verified_finding_fields(
                finding,
                verifier,
                task_target_id=str(resolver_task.get("target_id", "")),
                task_target_card_digest=str(resolver_task.get("target_card_digest", "")),
            )
            self._validate_canonical_pair_identity(
                resolver_task, verifier, resolved.get("pairs")
            )

        with self._canonical_evidence_lock(owned_evidence_dir):
            with self._lock:
                with self._file_lock():
                    latest = self._latest_unlocked()
                    task = latest.get(task_id)
                    if task is None:
                        raise KeyError(f"unknown_task:{task_id}")
                    task = dict(task)
                    if self._task_resolution_snapshot(task, task_dir) != resolver_task:
                        raise ValueError("task_changed_during_verifier_resolution")
                    final_evidence_dir = self._task_owned_evidence_dir(task_dir, owned_evidence_dir)
                    if final_evidence_dir != owned_evidence_dir:
                        raise ValueError("evidence_dir_changed_during_verifier_resolution")
                    final_binding = self._validate_task_evidence_binding(resolver_task, task_dir)
                    if final_binding != initial_binding:
                        raise ValueError("task_evidence_binding_changed_during_verification")

                    # Existing verifier writers use finding_write_lock(). Keep
                    # it through final validation and JSONL durability so their
                    # canonical evidence cannot move between the receipt check
                    # and the published record.
                    final_resolved = self._resolve_canonical_verified_finding(resolver_task, final_evidence_dir)
                    if not isinstance(final_resolved, dict):
                        raise ValueError("verifier_resolver_result_invalid")
                    final_finding = final_resolved.get("finding")
                    final_verifier = final_resolved.get("verifier")
                    if not isinstance(final_finding, dict) or not isinstance(final_verifier, dict):
                        raise ValueError("verifier_resolver_result_invalid")
                    safe_finding, safe_verifier = self._verified_finding_fields(
                        final_finding,
                        final_verifier,
                        task_target_id=str(resolver_task.get("target_id", "")),
                        task_target_card_digest=str(resolver_task.get("target_card_digest", "")),
                    )
                    self._validate_canonical_pair_identity(
                        resolver_task, final_verifier, final_resolved.get("pairs")
                    )
                    if (
                        initial_finding["finding_id"] != safe_finding["finding_id"]
                        or initial_verifier["record_digest"] != safe_verifier["record_digest"]
                        or initial_verifier["input_manifest_digest"] != safe_verifier["input_manifest_digest"]
                    ):
                        raise ValueError("canonical_verifier_changed_during_publish")

                    ledger_path = task_dir / "verified_findings.jsonl"
                    if ledger_path.is_file():
                        for raw_line in ledger_path.read_text(encoding="utf-8").splitlines():
                            try:
                                entry = json.loads(raw_line)
                            except json.JSONDecodeError:
                                continue
                            if not isinstance(entry, dict):
                                continue
                            prior = entry.get("finding") if isinstance(entry.get("finding"), dict) else {}
                            if prior.get("finding_id") == safe_finding["finding_id"]:
                                prior_verifier = entry.get("verifier") if isinstance(entry.get("verifier"), dict) else {}
                                if (
                                    prior_verifier.get("record_digest") == safe_verifier["record_digest"]
                                    and prior_verifier.get("input_manifest_digest") == safe_verifier["input_manifest_digest"]
                                ):
                                    return {"duplicate": True, "record": entry}
                                raise ValueError("verified_finding_provenance_conflict")
                    record = {
                        "schema": "TaskVerifiedFinding/v1",
                        "event": "verified_finding",
                        "task_id": task_id,
                        "task_target": str(task.get("target", "")),
                        "target_identity_binding": "target_card" if resolver_task.get("target_card_digest") else "unresolved_dependency",
                        "target_id": str(resolver_task.get("target_id", "")) or None,
                        "target_card_digest": str(resolver_task.get("target_card_digest", "")) or None,
                        "task_binding": final_binding,
                        "task_binding_digest": self._task_binding_digest(final_binding),
                        "evidence_ref": final_evidence_dir.relative_to(task_dir).as_posix(),
                        "evidence_manifest_digest": safe_verifier["input_manifest_digest"],
                        "published_ts": time.time(),
                        "finding": safe_finding,
                        "verifier": safe_verifier,
                    }
                    ledger_path.parent.mkdir(parents=True, exist_ok=True)
                    with ledger_path.open("a", encoding="utf-8") as handle:
                        handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
                        handle.flush()
                        os.fsync(handle.fileno())

        self._emit_event("verified_finding", {**task, "finding": safe_finding})
        return {"duplicate": False, "record": record}

    def submit(
        self,
        target: str,
        instruction: str,
        *,
        user_id: str = "",
        chat_id: str = "",
        goal_id: str = "",
        profile_name: str = "",
        target_card_digest: str = "",
        target_id: str = "",
        idempotency_key: str = "",
    ) -> Dict[str, Any]:
        target = target.strip()
        instruction = instruction.strip()
        goal_id = goal_id.strip()
        profile_name = profile_name.strip()
        target_card_digest = target_card_digest.strip().lower()
        target_id = target_id.strip()
        idempotency_key = idempotency_key.strip()
        if not target or not instruction:
            raise ValueError("target_and_instruction_required")
        if not goal_id or not profile_name or not idempotency_key:
            raise ValueError("goal_id_profile_name_and_idempotency_key_required")
        if not target_id or not target_card_digest:
            raise ValueError("target_identity_binding_required")
        if re.fullmatch(r"[0-9a-f]{64}", target_card_digest) is None:
            raise ValueError("target_card_digest_invalid")
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", target_id) is None:
            raise ValueError("target_identity_binding_required")

        with self._lock:
            with self._file_lock():
                latest = self._latest_unlocked()
                self._promote_recovery_pending_unlocked(latest)
                replay = self._find_by_idempotency(latest, idempotency_key)
                if replay is not None:
                    self._validate_replay(
                        replay,
                        target=target,
                        instruction=instruction,
                        goal_id=goal_id,
                        profile_name=profile_name,
                        target_id=target_id,
                        target_card_digest=target_card_digest,
                    )
                    if replay.get("status") in {"recovery_pending", "interrupted"}:
                        raise TaskRecoveryRequired(f"recovery_required:{replay['id']}")
                    if replay.get("status") != "reserved":
                        return replay
                    active = self._active_task(latest)
                    if active is not None:
                        if active.get("status") == "recovery_pending":
                            raise TaskRecoveryRequired(f"recovery_required:{active['id']}")
                        raise BusyError(str(active.get("id", "unknown")))
                    if self._running is not None:
                        raise BusyError(self._running)
                    task = self._activate_reservation_unlocked(replay)
                else:
                    active = self._active_task(latest)
                    if active is not None:
                        if active.get("status") == "recovery_pending":
                            raise TaskRecoveryRequired(f"recovery_required:{active['id']}")
                        raise BusyError(str(active.get("id", "unknown")))
                    if self._running is not None:
                        raise BusyError(self._running)

                    task_id = self._next_id(latest)
                    task = {
                        "event": "reserved",
                        "id": task_id,
                        "goal_id": goal_id,
                        "profile_name": profile_name,
                        "target_id": target_id,
                        "target_card_digest": target_card_digest,
                        "idempotency_key": idempotency_key,
                        "target": target,
                        "instruction": instruction,
                        "status": "reserved",
                        "reserved_ts": time.time(),
                        "owner_pid": os.getpid(),
                        "scan_mode": self.scan_mode,
                        "timeout_seconds": self.timeout,
                        "user_id": user_id,
                        "chat_id": chat_id,
                        "output_path": str(self._task_dir(task_id)),
                    }
                    self._append_unlocked(task)
                    task = self._activate_reservation_unlocked(task)
                task_id = str(task["id"])
                self._running = task_id

        start_gate = threading.Event()
        thread = threading.Thread(target=self._run_after_start, args=(dict(task), start_gate), daemon=True)
        thread.start()
        try:
            self._emit_event("started", task)
        finally:
            start_gate.set()
        return dict(task)

    def _run_after_start(self, task: Dict[str, Any], start_gate: threading.Event) -> None:
        start_gate.wait()
        self._run(task)

    @staticmethod
    def _append_runner_log(log_path: Path, line: str) -> bool:
        try:
            with log_path.open("a", encoding="utf-8") as handle:
                handle.write(line)
            return True
        except OSError:
            return False

    def _run(self, task: Dict[str, Any]) -> None:
        task_dir = self._task_dir(str(task["id"]))
        log_path = task_dir / "strix.log"
        command = [
            self.strix_bin,
            "-t",
            task["target"],
            "--instruction",
            task["instruction"] + "\n" + SCOPE_SUFFIX,
            "-n",
            "-m",
            str(task["scan_mode"]),
        ]
        progress_stop = threading.Event()
        progress_thread: Optional[threading.Thread] = None
        if self.event_fn is not None:
            progress_thread = threading.Thread(
                target=self._emit_periodic_progress,
                args=(dict(task), progress_stop),
                daemon=True,
            )
            progress_thread.start()
        blocked_reason = ""
        runner_reported_blocked = False
        runner_log_state = "written"
        try:
            exit_code = self.runner(command, task_dir, dict(os.environ), log_path, int(task["timeout_seconds"]))
        except RunnerBlockedError as exc:
            exit_code = RUNNER_BLOCKED_EXIT_CODE
            blocked_reason = exc.code
            runner_reported_blocked = True
            if not self._append_runner_log(log_path, f"runner_blocked:{blocked_reason}\n"):
                runner_log_state = "write_failed"
        except Exception:
            exit_code = 1
            if not self._append_runner_log(log_path, "runner_error:runner_failed\n"):
                runner_log_state = "write_failed"
        finally:
            progress_stop.set()
            if progress_thread is not None:
                progress_thread.join()
        report = self._find_report(task_dir)
        status = "blocked" if runner_reported_blocked else (
            "finished" if exit_code == 0 else ("timeout" if exit_code == 124 else "failed")
        )
        final = {
            "event": status,
            "id": task["id"],
            "status": status,
            "exit_code": exit_code,
            "finished_ts": time.time(),
            "report_path": str(report) if report else "",
            "output_path": str(task_dir),
        }
        if runner_log_state != "written":
            final["runner_log_state"] = runner_log_state
        if status == "blocked":
            final["blocked_reason"] = blocked_reason or "tool_runner_blocked"
        finalized = False
        try:
            with self._lock:
                with self._file_lock():
                    self._append_unlocked(final)
            finalized = True
        except Exception as exc:
            error = {
                "event": "finalization_error",
                "task_id": task["id"],
                "intended_status": status,
                "error": f"{type(exc).__name__}:{exc}",
                "ts": time.time(),
            }
            try:
                self._finalization_error_path(str(task["id"])).write_text(
                    json.dumps(error, ensure_ascii=False, indent=2, sort_keys=True),
                    encoding="utf-8",
                )
            except OSError:
                pass
        finally:
            with self._lock:
                if self._running == task["id"]:
                    self._running = None
        if finalized:
            self._notify(task, status, report)
            self._emit_event(status, {**task, **final})

    def _emit_periodic_progress(self, task: Dict[str, Any], stop: threading.Event) -> None:
        started_at = float(task.get("created_ts") or time.time())
        while not stop.wait(self.progress_interval):
            self._emit_event(
                "progress",
                {**task, "elapsed_seconds": max(0.0, time.time() - started_at)},
            )

    @staticmethod
    def _find_report(task_dir: Path) -> Optional[Path]:
        reports = sorted(
            task_dir.glob("strix_runs/*/penetration_test_report.md"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        return reports[0] if reports else None

    def _notify(self, task: Dict[str, Any], status: str, report: Optional[Path]) -> None:
        if self.notify_fn is None or not task.get("chat_id"):
            return
        label = {"finished": "完成", "failed": "失败", "timeout": "超时", "blocked": "已阻断"}[status]
        try:
            from confidentiality import external_target_label, safe_external_identifier
        except ModuleNotFoundError:
            from core.confidentiality import external_target_label, safe_external_identifier
        lines = [
            f"任务 {safe_external_identifier(task['id'])} {label}",
            f"目标：{external_target_label(task['target'])}",
        ]
        if report is not None:
            lines.append("报告状态：已生成；完整报告和证据仅保存在本机")
        else:
            lines.append("执行记录：已保存")
        lines.append("回复 1 查看脱敏任务状态")
        try:
            self.notify_fn(task["chat_id"], "\n".join(lines))
        except Exception:
            return

    def _emit_event(self, kind: str, task: Dict[str, Any]) -> None:
        if self.event_fn is None:
            return
        with self._event_lock:
            self._pending_events.append((kind, dict(task)))
            if self._event_dispatcher_running:
                return
            self._event_dispatcher_running = True
        threading.Thread(target=self._drain_events, daemon=True).start()

    def _drain_events(self) -> None:
        """Deliver lifecycle events in order without delaying task submission."""
        while True:
            with self._event_lock:
                if not self._pending_events:
                    self._event_dispatcher_running = False
                    return
                kind, task = self._pending_events.pop(0)
            try:
                self.event_fn(kind, task)
            except Exception:
                continue


def _self_test() -> int:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        calls: List[List[str]] = []

        def runner(command, cwd, env, log_path, timeout):
            calls.append(command)
            report_dir = Path(cwd) / "strix_runs" / "self-test"
            report_dir.mkdir(parents=True)
            (report_dir / "penetration_test_report.md").write_text("# report", encoding="utf-8")
            Path(log_path).write_text("ok", encoding="utf-8")
            return 0

        manager = TaskManager(root / "tasks.jsonl", root / "runs", runner=runner)
        task = manager.submit(
            "https://example.test",
            "/goal https://example.test",
            goal_id="G-self-test",
            profile_name="standard-pentest",
            idempotency_key="G-self-test",
        )
        for _ in range(50):
            if manager.list_tasks()[0]["status"] != "running":
                break
            time.sleep(0.02)
        replay = TaskManager(root / "tasks.jsonl", root / "runs", runner=runner).submit(
            "https://example.test",
            "/goal https://example.test",
            goal_id="G-self-test",
            profile_name="standard-pentest",
            idempotency_key="G-self-test",
        )
        assert task["id"] == replay["id"]
        assert len(calls) == 1
    print("task_router self-test ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())
