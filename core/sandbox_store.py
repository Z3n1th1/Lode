"""Pinned, create-once storage for synthetic sandbox run cards."""
from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path
from typing import List, Tuple

from quarantine_importer import (
    QuarantineImportError,
    absolute_lexical,
    ensure_existing_safe_directory,
    is_reparse,
    read_stable_bytes,
)


class SandboxStoreError(RuntimeError):
    """A sandbox card path could not be safely pinned or used."""


def _leaf_name(value: str, label: str) -> str:
    if type(value) is not str or not value or value in {".", ".."} or "/" in value or "\\" in value:
        raise SandboxStoreError(f"{label}_invalid")
    return value


def _stat_identity(info: os.stat_result) -> Tuple[int, ...]:
    return (
        int(getattr(info, "st_dev", 0)),
        int(getattr(info, "st_ino", 0)),
        int(stat.S_IFMT(info.st_mode)),
    )


def _require_private_directory(info: os.stat_result, *, owner_uid: int) -> None:
    if (
        not stat.S_ISDIR(info.st_mode)
        or int(getattr(info, "st_uid", -1)) != owner_uid
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise SandboxStoreError("sandbox_directory_private_required")


def _read_fd_bytes(descriptor: int, max_bytes: int, label: str) -> bytes:
    before = os.fstat(descriptor)
    if is_reparse(before) or not stat.S_ISREG(before.st_mode) or int(before.st_nlink) != 1:
        raise SandboxStoreError(f"{label}_invalid")
    if int(before.st_size) > max_bytes:
        raise SandboxStoreError(f"{label}_too_large")
    chunks: List[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(1024 * 1024, max_bytes - total + 1))
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise SandboxStoreError(f"{label}_too_large")
        chunks.append(chunk)
    after = os.fstat(descriptor)
    if _stat_identity(before) != _stat_identity(after) or total != int(after.st_size):
        raise SandboxStoreError(f"{label}_changed")
    return b"".join(chunks)


def _write_fd_bytes(descriptor: int, payload: bytes, label: str) -> None:
    view = memoryview(payload)
    offset = 0
    while offset < len(view):
        written = os.write(descriptor, view[offset:])
        if written <= 0:
            raise SandboxStoreError(f"{label}_short_write")
        offset += written
    os.fsync(descriptor)
    info = os.fstat(descriptor)
    if is_reparse(info) or not stat.S_ISREG(info.st_mode) or int(info.st_nlink) != 1:
        raise SandboxStoreError(f"{label}_invalid")


def _windows_open_directory(path: Path, *, pin: bool) -> int:
    import ctypes
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
    share_mode = 0x00000001 | 0x00000002
    if not pin:
        share_mode |= 0x00000004
    handle = create_file(
        str(path),
        0x00000001,
        share_mode,
        None,
        3,
        0x00200000 | 0x02000000,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle is None or handle == invalid_handle:
        raise OSError(ctypes.get_last_error() or 1, "sandbox_directory_open_failed")
    return int(handle)


def _windows_close_handle(handle: int) -> None:
    import ctypes
    from ctypes import wintypes

    close_handle = ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    if not close_handle(handle):
        raise OSError(ctypes.get_last_error() or 1, "sandbox_directory_close_failed")


def _windows_directory_identity(handle: int) -> Tuple[int, ...]:
    import ctypes
    from ctypes import wintypes

    class ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    get_information = ctypes.WinDLL("kernel32", use_last_error=True).GetFileInformationByHandle
    get_information.argtypes = [wintypes.HANDLE, ctypes.POINTER(ByHandleFileInformation)]
    get_information.restype = wintypes.BOOL
    information = ByHandleFileInformation()
    if not get_information(handle, ctypes.byref(information)):
        raise OSError(ctypes.get_last_error() or 1, "sandbox_directory_identity_failed")
    attributes = int(information.dwFileAttributes)
    if attributes & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)) or not attributes & 0x10:
        raise SandboxStoreError("sandbox_directory_invalid")
    return (
        int(information.dwVolumeSerialNumber),
        (int(information.nFileIndexHigh) << 32) | int(information.nFileIndexLow),
    )


def _windows_path_identity(path: Path) -> Tuple[int, ...]:
    handle = _windows_open_directory(path, pin=False)
    try:
        return _windows_directory_identity(handle)
    finally:
        _windows_close_handle(handle)


def _windows_move_file_no_replace(source: Path, target: Path) -> None:
    import ctypes
    from ctypes import wintypes

    move_file_ex = ctypes.WinDLL("kernel32", use_last_error=True).MoveFileExW
    move_file_ex.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    move_file_ex.restype = wintypes.BOOL
    move_file_write_through = 0x00000008
    if move_file_ex(str(source), str(target), move_file_write_through):
        return
    error = ctypes.get_last_error() or 1
    if error in {80, 183}:
        raise FileExistsError(error, "sandbox_target_exists", str(target))
    raise OSError(error, "sandbox_atomic_publish_failed", str(target))


def _posix_rename_no_replace(source_fd: int, source: str, target_fd: int, target: str) -> None:
    import ctypes
    import errno

    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except (AttributeError, OSError) as exc:
        raise SandboxStoreError("sandbox_atomic_publish_unavailable") from exc
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    rename_no_replace = 0x00000001
    if renameat2(source_fd, os.fsencode(source), target_fd, os.fsencode(target), rename_no_replace) == 0:
        return
    error = ctypes.get_errno()
    if error in {errno.EEXIST, errno.ENOTEMPTY}:
        raise FileExistsError(error, "sandbox_target_exists", target)
    if error in {errno.ENOSYS, errno.EINVAL, getattr(errno, "ENOTSUP", errno.EINVAL)}:
        raise SandboxStoreError("sandbox_atomic_publish_unavailable")
    raise OSError(error, "sandbox_atomic_publish_failed", target)


class PinnedDirectory:
    def __init__(self, root: Path, path: Path) -> None:
        self.root = ensure_existing_safe_directory(root, "sandbox_runs_root")
        self.path = ensure_existing_safe_directory(path, "sandbox_directory")
        try:
            relative = self.path.relative_to(self.root)
        except ValueError as exc:
            raise SandboxStoreError("sandbox_directory_outside_root") from exc
        self._windows_pins: List[Tuple[Path, int, Tuple[int, ...]]] = []
        self._posix_pins: List[Tuple[Path, int, Tuple[int, ...]]] = []
        self._closed = False
        try:
            if os.name == "nt":
                candidates = [self.root]
                current = self.root
                for part in relative.parts:
                    current = current / part
                    candidates.append(current)
                for candidate in candidates:
                    handle = _windows_open_directory(candidate, pin=True)
                    self._windows_pins.append((candidate, handle, _windows_directory_identity(handle)))
            else:
                no_follow = int(getattr(os, "O_NOFOLLOW", 0))
                directory_flag = int(getattr(os, "O_DIRECTORY", 0))
                if not no_follow or not directory_flag:
                    raise SandboxStoreError("sandbox_directory_pinning_unavailable")
                root_fd = os.open(self.root, os.O_RDONLY | directory_flag | no_follow)
                root_info = os.fstat(root_fd)
                if is_reparse(root_info) or not stat.S_ISDIR(root_info.st_mode):
                    os.close(root_fd)
                    raise SandboxStoreError("sandbox_directory_invalid")
                self._posix_pins.append((self.root, root_fd, _stat_identity(root_info)))
                current_path = self.root
                current_fd = root_fd
                for part in relative.parts:
                    next_fd = os.open(part, os.O_RDONLY | directory_flag | no_follow, dir_fd=current_fd)
                    next_info = os.fstat(next_fd)
                    if is_reparse(next_info) or not stat.S_ISDIR(next_info.st_mode):
                        os.close(next_fd)
                        raise SandboxStoreError("sandbox_directory_invalid")
                    current_path = current_path / part
                    self._posix_pins.append((current_path, next_fd, _stat_identity(next_info)))
                    current_fd = next_fd
            self.assert_current()
        except OSError as exc:
            self.close()
            raise SandboxStoreError("sandbox_directory_invalid") from exc
        except BaseException:
            self.close()
            raise

    def __enter__(self) -> "PinnedDirectory":
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        self.close()

    @property
    def leaf_fd(self) -> int:
        self._ensure_open()
        if not self._posix_pins:
            raise SandboxStoreError("sandbox_directory_fd_unavailable")
        return self._posix_pins[-1][1]

    @property
    def identity(self) -> Tuple[int, ...]:
        self._ensure_open()
        if os.name == "nt":
            if not self._windows_pins:
                raise SandboxStoreError("sandbox_directory_identity_unavailable")
            return self._windows_pins[-1][2]
        if not self._posix_pins:
            raise SandboxStoreError("sandbox_directory_identity_unavailable")
        return self._posix_pins[-1][2]

    def _ensure_open(self) -> None:
        if self._closed:
            raise SandboxStoreError("sandbox_directory_closed")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for _, handle, _ in reversed(self._windows_pins):
            try:
                _windows_close_handle(handle)
            except OSError:
                pass
        self._windows_pins.clear()
        for _, descriptor, _ in reversed(self._posix_pins):
            try:
                os.close(descriptor)
            except OSError:
                pass
        self._posix_pins.clear()

    def assert_current(self) -> None:
        self._ensure_open()
        if os.name == "nt":
            try:
                for path, handle, identity in self._windows_pins:
                    if _windows_directory_identity(handle) != identity or _windows_path_identity(path) != identity:
                        raise SandboxStoreError("sandbox_directory_identity_changed")
            except OSError as exc:
                raise SandboxStoreError("sandbox_directory_identity_changed") from exc
            return
        for path, descriptor, identity in self._posix_pins:
            try:
                current_descriptor = os.fstat(descriptor)
            except OSError as exc:
                raise SandboxStoreError("sandbox_directory_identity_changed") from exc
            if _stat_identity(current_descriptor) != identity:
                raise SandboxStoreError("sandbox_directory_identity_changed")
            try:
                current = path.lstat()
            except OSError as exc:
                raise SandboxStoreError("sandbox_directory_identity_changed") from exc
            if is_reparse(current) or _stat_identity(current) != identity:
                raise SandboxStoreError("sandbox_directory_identity_changed")

    def make_child_directory(self, name: str) -> Tuple[Path, Tuple[int, ...]]:
        leaf = _leaf_name(name, "sandbox_directory_name")
        self.assert_current()
        if os.name == "nt":
            child = self.path / leaf
            try:
                child.mkdir()
            except FileExistsError:
                pass
            except OSError as exc:
                raise SandboxStoreError("sandbox_directory_invalid") from exc
            try:
                ensure_existing_safe_directory(child, "sandbox_directory")
                child_identity = _windows_path_identity(child)
            except (OSError, QuarantineImportError) as exc:
                raise SandboxStoreError("sandbox_directory_invalid") from exc
            self.assert_current()
            return child, child_identity
        try:
            os.mkdir(leaf, 0o700, dir_fd=self.leaf_fd)
        except FileExistsError:
            pass
        except OSError as exc:
            raise SandboxStoreError("sandbox_directory_invalid") from exc
        try:
            descriptor = os.open(
                leaf,
                os.O_RDONLY | int(getattr(os, "O_DIRECTORY", 0)) | int(getattr(os, "O_NOFOLLOW", 0)),
                dir_fd=self.leaf_fd,
            )
        except OSError as exc:
            raise SandboxStoreError("sandbox_directory_invalid") from exc
        try:
            info = os.fstat(descriptor)
            if is_reparse(info) or not stat.S_ISDIR(info.st_mode):
                raise SandboxStoreError("sandbox_directory_invalid")
            owner = getattr(os, "geteuid", None)
            if owner is None:
                raise SandboxStoreError("sandbox_directory_private_required")
            _require_private_directory(info, owner_uid=int(owner()))
            child_identity = _stat_identity(info)
        finally:
            os.close(descriptor)
        self.assert_current()
        return self.path / leaf, child_identity

    def exists_regular(self, name: str) -> bool:
        leaf = _leaf_name(name, "sandbox_entry_name")
        self.assert_current()
        if os.name == "nt":
            candidate = self.path / leaf
            if not os.path.lexists(candidate):
                return False
            info = candidate.lstat()
            if is_reparse(info) or not stat.S_ISREG(info.st_mode):
                raise SandboxStoreError("sandbox_entry_invalid")
            return True
        try:
            info = os.stat(leaf, dir_fd=self.leaf_fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        if is_reparse(info) or not stat.S_ISREG(info.st_mode):
            raise SandboxStoreError("sandbox_entry_invalid")
        return True

    def read_bytes(self, name: str, *, max_bytes: int, label: str) -> bytes:
        leaf = _leaf_name(name, "sandbox_entry_name")
        self.assert_current()
        if os.name == "nt":
            candidate = self.path / leaf
            try:
                raw, _ = read_stable_bytes(candidate, max_bytes=max_bytes, label=label)
            except QuarantineImportError as exc:
                reason = str(exc)
                if reason == f"{label}_changed_during_read":
                    raise SandboxStoreError(f"{label}_changed") from exc
                if reason == f"{label}_too_large":
                    raise SandboxStoreError(f"{label}_too_large") from exc
                raise SandboxStoreError(f"{label}_invalid") from exc
            self.assert_current()
            return raw
        try:
            before_entry = os.stat(leaf, dir_fd=self.leaf_fd, follow_symlinks=False)
            if (
                is_reparse(before_entry)
                or not stat.S_ISREG(before_entry.st_mode)
                or int(before_entry.st_nlink) != 1
            ):
                raise SandboxStoreError(f"{label}_invalid")
            descriptor = os.open(
                leaf,
                os.O_RDONLY | int(getattr(os, "O_NOFOLLOW", 0)) | int(getattr(os, "O_CLOEXEC", 0)),
                dir_fd=self.leaf_fd,
            )
        except OSError as exc:
            raise SandboxStoreError(f"{label}_invalid") from exc
        try:
            raw = _read_fd_bytes(descriptor, max_bytes, label)
        except OSError as exc:
            raise SandboxStoreError(f"{label}_invalid") from exc
        finally:
            os.close(descriptor)
        try:
            after_entry = os.stat(leaf, dir_fd=self.leaf_fd, follow_symlinks=False)
        except OSError as exc:
            raise SandboxStoreError(f"{label}_changed") from exc
        if (
            is_reparse(after_entry)
            or not stat.S_ISREG(after_entry.st_mode)
            or int(after_entry.st_nlink) != 1
            or _stat_identity(before_entry) != _stat_identity(after_entry)
        ):
            raise SandboxStoreError(f"{label}_changed")
        self.assert_current()
        return raw

    def move_bytes_once(self, source_name: str, target_name: str, label: str) -> None:
        source = _leaf_name(source_name, "sandbox_entry_name")
        target = _leaf_name(target_name, "sandbox_entry_name")
        self.assert_current()
        try:
            if os.name == "nt":
                _windows_move_file_no_replace(self.path / source, self.path / target)
                target_info = (self.path / target).lstat()
            else:
                _posix_rename_no_replace(self.leaf_fd, source, self.leaf_fd, target)
                os.fsync(self.leaf_fd)
                target_info = os.stat(target, dir_fd=self.leaf_fd, follow_symlinks=False)
        except FileExistsError:
            raise
        except SandboxStoreError:
            raise
        except OSError as exc:
            raise SandboxStoreError(f"{label}_publish_failed") from exc
        if is_reparse(target_info) or not stat.S_ISREG(target_info.st_mode) or int(target_info.st_nlink) != 1:
            raise SandboxStoreError(f"{label}_invalid")
        self.assert_current()

    def create_bytes_once(self, name: str, payload: bytes, label: str) -> None:
        leaf = _leaf_name(name, "sandbox_entry_name")
        self.assert_current()
        if os.name == "nt":
            candidate = self.path / leaf
            if os.path.lexists(candidate):
                raise FileExistsError(candidate)
            try:
                with candidate.open("xb") as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
            except FileExistsError:
                raise
            except OSError as exc:
                raise SandboxStoreError(f"{label}_write_failed") from exc
            self.assert_current()
            return
        try:
            descriptor = os.open(
                leaf,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | int(getattr(os, "O_NOFOLLOW", 0)),
                0o600,
                dir_fd=self.leaf_fd,
            )
        except FileExistsError:
            raise
        except OSError as exc:
            raise SandboxStoreError(f"{label}_write_failed") from exc
        try:
            _write_fd_bytes(descriptor, payload, label)
        finally:
            os.close(descriptor)
        self.assert_current()


class SandboxRunStore:
    """Pins a task and its create-once quarantine card directory for one run."""

    def __init__(self, runs_root: Path | str, task_dir: Path | str) -> None:
        self.runs_root = ensure_existing_safe_directory(runs_root, "sandbox_runs_root")
        self.task_dir = absolute_lexical(task_dir)
        try:
            relative = self.task_dir.relative_to(self.runs_root)
        except ValueError as exc:
            raise SandboxStoreError("sandbox_task_outside_runs_root") from exc
        if len(relative.parts) != 1:
            raise SandboxStoreError("sandbox_task_invalid")
        self._task_parent = PinnedDirectory(self.runs_root, self.task_dir)
        self._run_directory: PinnedDirectory | None = None

    def __enter__(self) -> "SandboxRunStore":
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        self.close()

    def close(self) -> None:
        if self._run_directory is not None:
            self._run_directory.close()
            self._run_directory = None
        self._task_parent.close()

    def assert_current(self) -> None:
        self._task_parent.assert_current()
        if self._run_directory is not None:
            self._run_directory.assert_current()

    def read_scope_bytes(self, *, max_bytes: int) -> bytes:
        return self._task_parent.read_bytes("scope.json", max_bytes=max_bytes, label="sandbox_scope")

    def prepare_run(self, run_id: str) -> None:
        run_leaf = _leaf_name(run_id, "sandbox_run_id")
        quarantine_root, _ = self._task_parent.make_child_directory("quarantine")
        with PinnedDirectory(self.runs_root, quarantine_root) as quarantine_parent:
            run_path, created_identity = quarantine_parent.make_child_directory(run_leaf)
            next_run_directory = PinnedDirectory(self.runs_root, run_path)
            if next_run_directory.identity != created_identity:
                next_run_directory.close()
                raise SandboxStoreError("sandbox_directory_identity_changed")
        previous_run_directory = self._run_directory
        self._run_directory = next_run_directory
        if previous_run_directory is not None:
            previous_run_directory.close()

    def card_exists(self) -> bool:
        if self._run_directory is None:
            raise SandboxStoreError("sandbox_run_directory_unprepared")
        return self._run_directory.exists_regular("sandbox-run.json")

    def read_card_bytes(self, *, max_bytes: int) -> bytes:
        if self._run_directory is None:
            raise SandboxStoreError("sandbox_run_directory_unprepared")
        return self._run_directory.read_bytes("sandbox-run.json", max_bytes=max_bytes, label="sandbox_run_card")

    def publish_card_once(self, payload: bytes) -> None:
        if self._run_directory is None:
            raise SandboxStoreError("sandbox_run_directory_unprepared")
        stage_name = f".sandbox-run-{secrets.token_hex(16)}.stage"
        self._run_directory.create_bytes_once(stage_name, payload, "sandbox_run_card")
        self._run_directory.move_bytes_once(stage_name, "sandbox-run.json", "sandbox_run_card")
