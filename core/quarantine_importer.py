"""Static-only, no-follow inspection for third-party tool sources."""
from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Mapping, Tuple


MAX_QUARANTINE_SOURCE_BYTES = 8 * 1024 * 1024
_REPARSE_FLAG = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
# Windows updates ``st_ctime_ns`` while opening a file (it is a creation/access
# timestamp there), so it is not a stable identity field.  Treating it as one
# made every normal quarantine read look like a TOCTOU change on Windows.
_IDENTITY_FIELDS = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
if os.name != "nt":
    _IDENTITY_FIELDS = _IDENTITY_FIELDS + ("st_ctime_ns",)


class QuarantineImportError(ValueError):
    """A source or its receipt could not enter the quarantine-only intake."""


def _canonical_digest(value: Mapping[str, Any]) -> str:
    text = json.dumps(dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def absolute_lexical(path: Path | str) -> Path:
    """Normalize a path without resolving links or reparse points."""
    return Path(os.path.abspath(os.fspath(path)))


def is_reparse(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        int(getattr(info, "st_file_attributes", 0)) & _REPARSE_FLAG
    )


def assert_existing_components_no_follow(path: Path, label: str) -> None:
    """Reject every existing symlink/reparse component in a lexical path."""
    absolute = absolute_lexical(path)
    current = Path(absolute.anchor) if absolute.anchor else Path()
    parts = absolute.parts[1:] if absolute.anchor else absolute.parts
    for part in parts:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise QuarantineImportError(f"{label}_unavailable") from exc
        if is_reparse(info):
            raise QuarantineImportError(f"{label}_reparse_component")


def ensure_existing_safe_directory(path: Path | str, label: str) -> Path:
    absolute = absolute_lexical(path)
    assert_existing_components_no_follow(absolute, label)
    try:
        info = absolute.lstat()
    except OSError as exc:
        raise QuarantineImportError(f"{label}_invalid") from exc
    if is_reparse(info) or not stat.S_ISDIR(info.st_mode):
        raise QuarantineImportError(f"{label}_invalid")
    return absolute


def ensure_safe_directory(path: Path | str, label: str) -> Path:
    absolute = absolute_lexical(path)
    try:
        ensure_existing_safe_directory(absolute.parent, label)
        absolute.mkdir()
    except FileExistsError:
        pass
    except OSError as exc:
        raise QuarantineImportError(f"{label}_invalid") from exc
    return ensure_existing_safe_directory(absolute, label)


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return all(getattr(left, field, None) == getattr(right, field, None) for field in _IDENTITY_FIELDS)


def _directory_identity(info: os.stat_result) -> Tuple[int, ...]:
    return (int(getattr(info, "st_dev", 0)), int(getattr(info, "st_ino", 0)), int(stat.S_IFMT(info.st_mode)))


def _open_binary_no_follow(path: Path):
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0)) | int(getattr(os, "O_NOINHERIT", 0))
    no_follow = int(getattr(os, "O_NOFOLLOW", 0))
    if os.name != "nt":
        if not no_follow:
            raise QuarantineImportError("quarantine_no_follow_unavailable")
        return os.fdopen(os.open(path, flags | no_follow), "rb")

    import ctypes
    import msvcrt
    from ctypes import wintypes

    create_file = ctypes.WinDLL("kernel32", use_last_error=True).CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    handle = create_file(
        str(path),
        0x80000000,
        0x00000001 | 0x00000002 | 0x00000004,
        None,
        3,
        0x00200000 | 0x08000000,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle == invalid_handle:
        raise QuarantineImportError("quarantine_no_follow_open_failed")
    try:
        descriptor = msvcrt.open_osfhandle(handle, flags)
    except BaseException:
        ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(handle)
        raise
    return os.fdopen(descriptor, "rb")


def read_stable_bytes(path: Path | str, *, max_bytes: int, label: str) -> Tuple[bytes, os.stat_result]:
    """Read one bounded regular file while rejecting link/reparse path changes."""
    if type(max_bytes) is not int or max_bytes <= 0:
        raise QuarantineImportError(f"{label}_read_cap_invalid")
    absolute = absolute_lexical(path)
    assert_existing_components_no_follow(absolute.parent, label)
    try:
        before = absolute.lstat()
    except OSError as exc:
        raise QuarantineImportError(f"{label}_unavailable") from exc
    if is_reparse(before) or not stat.S_ISREG(before.st_mode) or int(before.st_nlink) != 1:
        raise QuarantineImportError(f"{label}_invalid")
    if int(before.st_size) > max_bytes:
        raise QuarantineImportError(f"{label}_too_large")

    chunks: list[bytes] = []
    total = 0
    try:
        handle = _open_binary_no_follow(absolute)
    except QuarantineImportError:
        raise
    except OSError as exc:
        raise QuarantineImportError(f"{label}_unavailable") from exc
    with handle:
        opened = os.fstat(handle.fileno())
        if is_reparse(opened) or not stat.S_ISREG(opened.st_mode) or not _same_identity(before, opened):
            raise QuarantineImportError(f"{label}_changed_during_read")
        while True:
            chunk = handle.read(min(1024 * 1024, max_bytes - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise QuarantineImportError(f"{label}_too_large")
            chunks.append(chunk)

    try:
        after = absolute.lstat()
    except OSError as exc:
        raise QuarantineImportError(f"{label}_changed_during_read") from exc
    if is_reparse(after) or not _same_identity(before, after) or total != int(after.st_size):
        raise QuarantineImportError(f"{label}_changed_during_read")
    assert_existing_components_no_follow(absolute, label)
    return b"".join(chunks), after


class QuarantineImporter:
    """Fingerprint one source file without importing, parsing, or executing it."""

    _RECEIPT_KEYS = {
        "schema",
        "state",
        "source_relative_path",
        "source_sha256",
        "source_bytes",
        "inspection_mode",
        "source_executed",
        "receipt_sha256",
    }

    def __init__(self, source_root: Path, *, max_source_bytes: int = MAX_QUARANTINE_SOURCE_BYTES) -> None:
        if type(max_source_bytes) is not int or max_source_bytes <= 0:
            raise ValueError("quarantine_max_source_bytes_invalid")
        self._root = ensure_existing_safe_directory(source_root, "quarantine_source_root")
        self._root_identity = _directory_identity(self._root.lstat())
        self._max_source_bytes = max_source_bytes

    def _assert_root_identity(self) -> None:
        try:
            current = ensure_existing_safe_directory(self._root, "quarantine_source_root")
            info = current.lstat()
        except QuarantineImportError as exc:
            raise QuarantineImportError("quarantine_source_invalid") from exc
        if _directory_identity(info) != self._root_identity:
            raise QuarantineImportError("quarantine_source_invalid")

    def canonical_source_path(self, source: Path | str) -> Path:
        absolute = absolute_lexical(source)
        try:
            relative = absolute.relative_to(self._root)
        except ValueError as exc:
            raise QuarantineImportError("quarantine_source_outside_root") from exc
        if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
            raise QuarantineImportError("quarantine_source_invalid")
        try:
            assert_existing_components_no_follow(absolute, "quarantine_source")
        except QuarantineImportError as exc:
            raise QuarantineImportError("quarantine_source_invalid") from exc
        return absolute

    @staticmethod
    def _validate_relative_path(value: Any) -> bool:
        if not isinstance(value, str) or not value:
            return False
        candidate = PurePosixPath(value)
        return not candidate.is_absolute() and bool(candidate.parts) and all(
            part not in {"", ".", ".."} for part in candidate.parts
        )

    @classmethod
    def validate_receipt(cls, receipt: Mapping[str, Any]) -> Dict[str, Any]:
        candidate = dict(receipt)
        if set(candidate) != cls._RECEIPT_KEYS:
            raise QuarantineImportError("quarantine_receipt_invalid")
        if (
            candidate.get("schema") != "ToolQuarantineReceipt/v1"
            or candidate.get("state") != "quarantined"
            or candidate.get("inspection_mode") != "static_only"
            or candidate.get("source_executed") is not False
            or not cls._validate_relative_path(candidate.get("source_relative_path"))
            or type(candidate.get("source_bytes")) is not int
            or candidate["source_bytes"] < 0
            or not isinstance(candidate.get("source_sha256"), str)
            or len(candidate["source_sha256"]) != 64
            or any(character not in "0123456789abcdef" for character in candidate["source_sha256"])
            or not isinstance(candidate.get("receipt_sha256"), str)
        ):
            raise QuarantineImportError("quarantine_receipt_invalid")
        expected_digest = _canonical_digest({key: value for key, value in candidate.items() if key != "receipt_sha256"})
        if candidate["receipt_sha256"] != expected_digest:
            raise QuarantineImportError("quarantine_receipt_invalid")
        return candidate

    def inspect(self, source: Path | str) -> Dict[str, Any]:
        from sandbox_store import PinnedDirectory, SandboxStoreError

        try:
            absolute = self.canonical_source_path(source)
            relative = absolute.relative_to(self._root)
            self._assert_root_identity()
            with PinnedDirectory(self._root, absolute.parent) as parent:
                source_bytes = parent.read_bytes(
                    absolute.name,
                    max_bytes=self._max_source_bytes,
                    label="quarantine_source",
                )
            self._assert_root_identity()
        except SandboxStoreError as exc:
            raise QuarantineImportError("quarantine_source_invalid") from exc
        except QuarantineImportError as exc:
            if str(exc) == "quarantine_source_outside_root":
                raise
            raise QuarantineImportError("quarantine_source_invalid") from exc

        receipt: Dict[str, Any] = {
            "schema": "ToolQuarantineReceipt/v1",
            "state": "quarantined",
            "source_relative_path": relative.as_posix(),
            "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
            "source_bytes": len(source_bytes),
            "inspection_mode": "static_only",
            "source_executed": False,
        }
        receipt["receipt_sha256"] = _canonical_digest(receipt)
        return receipt

    def verify_receipt(self, source: Path | str, receipt: Mapping[str, Any]) -> Dict[str, Any]:
        expected = self.validate_receipt(receipt)
        current = self.inspect(source)
        if current != expected:
            raise QuarantineImportError("quarantine_source_changed")
        return current
