"""Regression contract for the quarantine-only ToolRunner core."""
from __future__ import annotations

import json
import hashlib
import sys
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path


PENTEST_AGENT = Path(__file__).resolve().parents[1]
for directory in (PENTEST_AGENT / "core", PENTEST_AGENT / "notify"):
    sys.path.insert(0, str(directory))


class ToolRunnerTests(unittest.TestCase):
    @staticmethod
    def _write_source(root: Path, name: str = "tool.py") -> tuple[Path, Path]:
        source = root / name
        sentinel = root / "executed.txt"
        source.write_text(
            "from pathlib import Path\n"
            f"Path({str(sentinel)!r}).write_text('executed', encoding='utf-8')\n",
            encoding="utf-8",
        )
        return source, sentinel

    @staticmethod
    def _write_scope(task_dir: Path, *, task_id: str = "T-001", run_id: str = "run-001") -> None:
        task_dir.mkdir(parents=True, exist_ok=True)
        (task_dir / "scope.json").write_text(
            json.dumps({"task_id": task_id, "run_id": run_id, "target": "https://example.test"}),
            encoding="utf-8",
        )

    @staticmethod
    def _runner(source_root: Path, source: Path, receipt: dict, runs_root: Path, *, uid: int = 1000):
        from quarantine_importer import QuarantineImporter
        from tool_runner import SyntheticToolRunner

        return SyntheticToolRunner(
            quarantine_importer=QuarantineImporter(source_root),
            source_path=source,
            quarantine_receipt=receipt,
            runs_root=runs_root,
            identity_provider=lambda: uid,
        )

    @staticmethod
    def _canonical_digest(value: dict) -> str:
        text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def test_quarantine_inspects_regular_source_without_importing_or_executing_it(self) -> None:
        from quarantine_importer import QuarantineImporter

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "sources"
            root.mkdir()
            source, sentinel = self._write_source(root)

            receipt = QuarantineImporter(root).inspect(source)

            self.assertFalse(sentinel.exists())

        self.assertEqual("ToolQuarantineReceipt/v1", receipt["schema"])
        self.assertEqual("quarantined", receipt["state"])
        self.assertEqual("tool.py", receipt["source_relative_path"])
        self.assertRegex(receipt["source_sha256"], r"^[0-9a-f]{64}$")

    def test_quarantine_reads_the_source_through_a_pinned_parent_directory(self) -> None:
        import quarantine_importer
        import sandbox_store
        from quarantine_importer import QuarantineImporter

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "sources"
            root.mkdir()
            source, _ = self._write_source(root)
            with mock.patch.object(
                quarantine_importer,
                "read_stable_bytes",
                side_effect=AssertionError("path_reader_must_not_be_used"),
            ):
                receipt = QuarantineImporter(root).inspect(source)
        self.assertEqual("quarantined", receipt["state"])

    def test_pinned_directory_maps_open_failures_to_a_store_error(self) -> None:
        import os
        import sandbox_store
        from sandbox_store import PinnedDirectory, SandboxStoreError

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            child = root / "child"
            child.mkdir()
            patch_target = (
                mock.patch.object(
                    sandbox_store, "_windows_open_directory", side_effect=PermissionError("synthetic_permission_failure")
                )
                if os.name == "nt"
                else mock.patch.object(sandbox_store.os, "open", side_effect=PermissionError("synthetic_permission_failure"))
            )
            with patch_target:
                with self.assertRaisesRegex(SandboxStoreError, "^sandbox_directory_invalid$"):
                    PinnedDirectory(root, child)

    def test_pinned_directory_returns_the_identity_of_a_created_child(self) -> None:
        from sandbox_store import PinnedDirectory

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            parent = root / "parent"
            parent.mkdir()
            with PinnedDirectory(root, parent) as directory:
                child, created_identity = directory.make_child_directory("child")
                with PinnedDirectory(root, child) as child_directory:
                    self.assertEqual(created_identity, child_directory.identity)

    def test_private_directory_validator_rejects_group_or_other_access(self) -> None:
        import os
        import stat
        from sandbox_store import SandboxStoreError, _require_private_directory

        info = os.stat_result((stat.S_IFDIR | 0o755, 0, 0, 2, 1000, 1000, 0, 0, 0, 0))
        with self.assertRaisesRegex(SandboxStoreError, "^sandbox_directory_private_required$"):
            _require_private_directory(info, owner_uid=1000)

    def test_pinned_directory_maps_identity_check_failures_to_a_store_error(self) -> None:
        import os
        import sandbox_store
        from sandbox_store import PinnedDirectory, SandboxStoreError

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            child = root / "child"
            child.mkdir()
            if os.name == "nt":
                failing_check = mock.patch.object(
                    sandbox_store, "_windows_path_identity", side_effect=PermissionError("synthetic_permission_failure")
                )
            else:
                failing_check = mock.patch.object(
                    Path, "lstat", side_effect=PermissionError("synthetic_permission_failure")
                )
            with PinnedDirectory(root, child) as directory, failing_check:
                with self.assertRaisesRegex(SandboxStoreError, "^sandbox_directory_identity_changed$"):
                    directory.assert_current()

    def test_quarantine_rejects_source_outside_the_declared_root(self) -> None:
        from quarantine_importer import QuarantineImportError, QuarantineImporter

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_root = root / "sources"
            source_root.mkdir()
            outside, sentinel = self._write_source(root, "outside.py")

            with self.assertRaisesRegex(QuarantineImportError, "^quarantine_source_outside_root$"):
                QuarantineImporter(source_root).inspect(outside)
            self.assertFalse(sentinel.exists())

    def test_synthetic_runner_rejects_root_identity_before_executor(self) -> None:
        from quarantine_importer import QuarantineImporter
        from tool_runner import SyntheticToolRunner, ToolRunnerError

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_root = root / "sources"
            source_root.mkdir()
            source, sentinel = self._write_source(source_root)
            receipt = QuarantineImporter(source_root).inspect(source)
            runs_root = root / "runs"
            task_dir = runs_root / "T-001"
            self._write_scope(task_dir)

            runner = SyntheticToolRunner(
                quarantine_importer=QuarantineImporter(source_root),
                source_path=source,
                quarantine_receipt=receipt,
                runs_root=runs_root,
                identity_provider=lambda: 0,
            )
            with self.assertRaisesRegex(ToolRunnerError, "^tool_runner_root_forbidden$"):
                runner([str(source)], task_dir, {"SECRET": "hidden"}, task_dir / "strix.log", 30)
            self.assertFalse(sentinel.exists())

    def test_synthetic_runner_rejects_a_changed_source_before_writing_a_card(self) -> None:
        from quarantine_importer import QuarantineImporter
        from tool_runner import SyntheticToolRunner, ToolRunnerError

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_root = root / "sources"
            source_root.mkdir()
            source, sentinel = self._write_source(source_root)
            receipt = QuarantineImporter(source_root).inspect(source)
            source.write_text("changed source", encoding="utf-8")
            runs_root = root / "runs"
            task_dir = runs_root / "T-001"
            self._write_scope(task_dir)

            runner = SyntheticToolRunner(
                quarantine_importer=QuarantineImporter(source_root),
                source_path=source,
                quarantine_receipt=receipt,
                runs_root=runs_root,
                identity_provider=lambda: 1000,
            )
            with self.assertRaisesRegex(ToolRunnerError, "^tool_quarantine_source_changed$"):
                runner([str(source)], task_dir, {"SECRET": "hidden"}, task_dir / "strix.log", 30)
            self.assertFalse((task_dir / "quarantine").exists())
            self.assertFalse(sentinel.exists())

    def test_synthetic_runner_binds_the_command_to_the_inspected_source(self) -> None:
        from quarantine_importer import QuarantineImporter
        from tool_runner import ToolRunnerError

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_root = root / "sources"
            source_root.mkdir()
            source, sentinel = self._write_source(source_root)
            receipt = QuarantineImporter(source_root).inspect(source)
            runs_root = root / "runs"
            task_dir = runs_root / "T-001"
            self._write_scope(task_dir)
            log_path = task_dir / "strix.log"
            runner = self._runner(source_root, source, receipt, runs_root)

            with self.assertRaisesRegex(ToolRunnerError, "^tool_runner_command_source_mismatch$"):
                runner(["not-the-inspected-tool"], task_dir, {"SECRET": "env-secret"}, log_path, 30)
            self.assertFalse((task_dir / "quarantine").exists())
            self.assertFalse(sentinel.exists())

    def test_synthetic_runner_writes_a_blocked_card_without_environment_values(self) -> None:
        from quarantine_importer import QuarantineImporter
        from runner_contract import RunnerBlockedError

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_root = root / "sources"
            source_root.mkdir()
            source, sentinel = self._write_source(source_root)
            receipt = QuarantineImporter(source_root).inspect(source)
            runs_root = root / "runs"
            task_dir = runs_root / "T-001"
            self._write_scope(task_dir)
            log_path = task_dir / "strix.log"
            runner = self._runner(source_root, source, receipt, runs_root)

            with self.assertRaisesRegex(RunnerBlockedError, "^synthetic_no_execution$"):
                runner([str(source), "--token", "command-secret"], task_dir, {"SECRET": "env-secret"}, log_path, 30)
            card_path = task_dir / "quarantine" / "run-001" / "sandbox-run.json"
            card_text = card_path.read_text(encoding="utf-8")
            card = json.loads(card_text)
            self.assertEqual("SandboxRunCard/v1", card["schema"])
            self.assertEqual("synthetic", card["execution_mode"])
            self.assertEqual("none", card["network"])
            self.assertFalse(card["rootless"])
            self.assertTrue(card["secret_exposed"] is False)
            self.assertEqual("blocked", card["status"])
            self.assertEqual("synthetic_no_execution", card["block_reason"])
            self.assertRegex(card["command_sha256"], r"^[0-9a-f]{64}$")
            self.assertNotIn("env-secret", card_text)
            self.assertNotIn("command-secret", card_text)
            self.assertFalse((task_dir / "evidence").exists())
            self.assertFalse(sentinel.exists())

    def test_synthetic_runner_rejects_a_tampered_completed_card_on_retry(self) -> None:
        from quarantine_importer import QuarantineImporter
        from runner_contract import RunnerBlockedError
        from tool_runner import ToolRunnerError

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_root = root / "sources"
            source_root.mkdir()
            source, _ = self._write_source(source_root)
            receipt = QuarantineImporter(source_root).inspect(source)
            runs_root = root / "runs"
            task_dir = runs_root / "T-001"
            self._write_scope(task_dir)
            runner = self._runner(source_root, source, receipt, runs_root)
            log_path = task_dir / "strix.log"
            with self.assertRaisesRegex(RunnerBlockedError, "^synthetic_no_execution$"):
                runner([str(source)], task_dir, {}, log_path, 30)
            card_path = task_dir / "quarantine" / "run-001" / "sandbox-run.json"
            card = json.loads(card_path.read_text(encoding="utf-8"))
            card["scope_sha256"] = "0" * 64
            card_path.write_text(json.dumps(card), encoding="utf-8")

            with self.assertRaisesRegex(ToolRunnerError, "^sandbox_run_card_invalid$"):
                runner([str(source)], task_dir, {}, log_path, 30)

    def test_synthetic_runner_uses_the_card_as_its_create_once_record_not_a_path_lock(self) -> None:
        from quarantine_importer import QuarantineImporter
        from runner_contract import RunnerBlockedError

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_root = root / "sources"
            source_root.mkdir()
            source, _ = self._write_source(source_root)
            receipt = QuarantineImporter(source_root).inspect(source)
            runs_root = root / "runs"
            task_dir = runs_root / "T-001"
            self._write_scope(task_dir)
            runner = self._runner(source_root, source, receipt, runs_root)

            with self.assertRaisesRegex(RunnerBlockedError, "^synthetic_no_execution$"):
                runner([str(source)], task_dir, {}, task_dir / "strix.log", 30)
            quarantine_dir = task_dir / "quarantine" / "run-001"
            self.assertTrue((quarantine_dir / "sandbox-run.json").is_file())
            self.assertFalse((quarantine_dir / "sandbox-run.lock").exists())

    def test_sandbox_store_does_not_publish_a_card_when_atomic_commit_fails(self) -> None:
        from sandbox_store import SandboxRunStore, SandboxStoreError

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runs_root = root / "runs"
            task_dir = runs_root / "T-001"
            self._write_scope(task_dir)

            with SandboxRunStore(runs_root, task_dir) as store:
                store.prepare_run("run-001")
                assert store._run_directory is not None
                with mock.patch.object(
                    store._run_directory,
                    "move_bytes_once",
                    side_effect=SandboxStoreError("sandbox_run_card_publish_failed"),
                ):
                    with self.assertRaisesRegex(SandboxStoreError, "^sandbox_run_card_publish_failed$"):
                        store.publish_card_once(b'{"state":"blocked"}\n')
                self.assertFalse(store.card_exists())

    def test_sandbox_store_can_retry_after_an_interrupted_stage_write(self) -> None:
        from sandbox_store import SandboxRunStore, SandboxStoreError

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runs_root = root / "runs"
            task_dir = runs_root / "T-001"
            self._write_scope(task_dir)
            payload = b'{"state":"blocked"}\n'

            with SandboxRunStore(runs_root, task_dir) as store:
                store.prepare_run("run-001")
                assert store._run_directory is not None

                def interrupted_stage_write(name, _payload, _label):
                    (store._run_directory.path / name).write_bytes(b"{")
                    raise SandboxStoreError("sandbox_run_card_write_failed")

                with mock.patch.object(store._run_directory, "create_bytes_once", side_effect=interrupted_stage_write):
                    with self.assertRaisesRegex(SandboxStoreError, "^sandbox_run_card_write_failed$"):
                        store.publish_card_once(payload)
                self.assertFalse(store.card_exists())

                store.publish_card_once(payload)
                self.assertEqual(payload, store.read_card_bytes(max_bytes=1024))

    def test_sandbox_store_replacing_a_run_pin_closes_the_previous_pin(self) -> None:
        from sandbox_store import SandboxRunStore, SandboxStoreError

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runs_root = root / "runs"
            task_dir = runs_root / "T-001"
            self._write_scope(task_dir)

            with SandboxRunStore(runs_root, task_dir) as store:
                store.prepare_run("run-001")
                previous = store._run_directory
                assert previous is not None
                try:
                    store.prepare_run("run-002")
                    with self.assertRaisesRegex(SandboxStoreError, "^sandbox_directory_closed$"):
                        previous.assert_current()
                finally:
                    previous.close()

    @unittest.skipIf(__import__("os").name == "nt", "private directory permissions are POSIX-only")
    def test_sandbox_store_rejects_a_non_private_existing_quarantine_directory(self) -> None:
        import os
        from sandbox_store import SandboxRunStore, SandboxStoreError

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runs_root = root / "runs"
            task_dir = runs_root / "T-001"
            self._write_scope(task_dir)
            quarantine_dir = task_dir / "quarantine"
            quarantine_dir.mkdir()
            os.chmod(quarantine_dir, 0o755)

            with SandboxRunStore(runs_root, task_dir) as store:
                with self.assertRaisesRegex(SandboxStoreError, "^sandbox_directory_private_required$"):
                    store.prepare_run("run-001")

    def test_synthetic_runner_rejects_boolean_card_values_even_with_a_matching_digest(self) -> None:
        from quarantine_importer import QuarantineImporter
        from runner_contract import RunnerBlockedError
        from tool_runner import ToolRunnerError

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_root = root / "sources"
            source_root.mkdir()
            source, _ = self._write_source(source_root)
            receipt = QuarantineImporter(source_root).inspect(source)
            runs_root = root / "runs"
            task_dir = runs_root / "T-001"
            self._write_scope(task_dir)
            runner = self._runner(source_root, source, receipt, runs_root)
            log_path = task_dir / "strix.log"
            with self.assertRaisesRegex(RunnerBlockedError, "^synthetic_no_execution$"):
                runner([str(source)], task_dir, {}, log_path, 30)
            card_path = task_dir / "quarantine" / "run-001" / "sandbox-run.json"
            card = json.loads(card_path.read_text(encoding="utf-8"))
            card["output"]["bytes"] = False
            card["card_sha256"] = self._canonical_digest({key: value for key, value in card.items() if key != "card_sha256"})
            card_path.write_text(json.dumps(card), encoding="utf-8")

            with self.assertRaisesRegex(ToolRunnerError, "^sandbox_run_card_invalid$"):
                runner([str(source)], task_dir, {}, log_path, 30)

    def test_quarantine_receipt_rejects_boolean_source_bytes_even_with_a_matching_digest(self) -> None:
        from quarantine_importer import QuarantineImportError, QuarantineImporter

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_root = root / "sources"
            source_root.mkdir()
            source, _ = self._write_source(source_root)
            receipt = QuarantineImporter(source_root).inspect(source)
            receipt["source_bytes"] = False
            receipt["receipt_sha256"] = self._canonical_digest(
                {key: value for key, value in receipt.items() if key != "receipt_sha256"}
            )

            with self.assertRaisesRegex(QuarantineImportError, "^quarantine_receipt_invalid$"):
                QuarantineImporter(source_root).validate_receipt(receipt)

    def test_synthetic_runner_reloads_scope_inside_the_card_lock(self) -> None:
        from quarantine_importer import QuarantineImporter

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_root = root / "sources"
            source_root.mkdir()
            source, _ = self._write_source(source_root)
            receipt = QuarantineImporter(source_root).inspect(source)
            runs_root = root / "runs"
            task_dir = runs_root / "T-001"
            self._write_scope(task_dir)
            runner = self._runner(source_root, source, receipt, runs_root)
            original_load_scope = runner._load_scope
            calls = 0

            def change_scope_after_first_read(scope_bytes: bytes):
                nonlocal calls
                result = original_load_scope(scope_bytes)
                calls += 1
                if calls == 1:
                    payload = json.loads((task_dir / "scope.json").read_text(encoding="utf-8"))
                    payload["revision"] = "changed-after-first-read"
                    (task_dir / "scope.json").write_text(json.dumps(payload), encoding="utf-8")
                return result

            with mock.patch.object(runner, "_load_scope", side_effect=change_scope_after_first_read):
                try:
                    runner([str(source)], task_dir, {}, task_dir / "strix.log", 30)
                except RuntimeError:
                    pass
            card = json.loads((task_dir / "quarantine" / "run-001" / "sandbox-run.json").read_text(encoding="utf-8"))
            expected_scope_digest = hashlib.sha256((task_dir / "scope.json").read_bytes()).hexdigest()
            self.assertEqual(3, calls)
            self.assertEqual(expected_scope_digest, card["scope_sha256"])

    def test_synthetic_runner_rejects_a_task_directory_outside_its_runs_root(self) -> None:
        from quarantine_importer import QuarantineImporter
        from tool_runner import ToolRunnerError

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_root = root / "sources"
            source_root.mkdir()
            source, _ = self._write_source(source_root)
            receipt = QuarantineImporter(source_root).inspect(source)
            runs_root = root / "runs"
            runs_root.mkdir()
            outside_task = root / "outside" / "T-001"
            self._write_scope(outside_task)
            runner = self._runner(source_root, source, receipt, runs_root)

            with self.assertRaisesRegex(ToolRunnerError, "^tool_runner_task_dir_outside_runs_root$"):
                runner([str(source)], outside_task, {}, outside_task / "runner.log", 30)

    def test_quarantine_rejects_a_parent_symlink(self) -> None:
        from quarantine_importer import QuarantineImportError, QuarantineImporter

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_root = root / "sources"
            source_root.mkdir()
            source, _ = self._write_source(source_root)
            linked_root = root / "linked-sources"
            try:
                linked_root.symlink_to(source_root, target_is_directory=True)
            except (NotImplementedError, OSError):
                self.skipTest("symlink_creation_unavailable")

            with self.assertRaisesRegex(QuarantineImportError, "^quarantine_source_invalid$"):
                QuarantineImporter(source_root).inspect(linked_root / source.name)

    def test_synthetic_runner_rejects_a_quarantine_parent_symlink(self) -> None:
        from quarantine_importer import QuarantineImporter
        from tool_runner import ToolRunnerError

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_root = root / "sources"
            source_root.mkdir()
            source, _ = self._write_source(source_root)
            receipt = QuarantineImporter(source_root).inspect(source)
            runs_root = root / "runs"
            task_dir = runs_root / "T-001"
            self._write_scope(task_dir)
            outside = root / "outside"
            outside.mkdir()
            try:
                (task_dir / "quarantine").symlink_to(outside, target_is_directory=True)
            except (NotImplementedError, OSError):
                self.skipTest("symlink_creation_unavailable")
            runner = self._runner(source_root, source, receipt, runs_root)

            with self.assertRaisesRegex(ToolRunnerError, "^tool_runner_quarantine_path_invalid$"):
                runner([str(source)], task_dir, {}, task_dir / "strix.log", 30)

    def test_synthetic_runner_maps_filesystem_errors_to_a_typed_runner_error(self) -> None:
        import sandbox_store
        from quarantine_importer import QuarantineImporter
        from tool_runner import ToolRunnerError

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_root = root / "sources"
            source_root.mkdir()
            source, _ = self._write_source(source_root)
            receipt = QuarantineImporter(source_root).inspect(source)
            runs_root = root / "runs"
            task_dir = runs_root / "T-001"
            self._write_scope(task_dir)
            runner = self._runner(source_root, source, receipt, runs_root)

            with mock.patch.object(
                sandbox_store.PinnedDirectory,
                "read_bytes",
                side_effect=PermissionError("synthetic_permission_failure"),
            ):
                with self.assertRaisesRegex(ToolRunnerError, "^tool_runner_quarantine_path_invalid$"):
                    runner([str(source)], task_dir, {}, task_dir / "strix.log", 30)

    @unittest.skipIf(__import__("os").name == "nt", "dir_fd leaf identity regression is POSIX-only")
    def test_pinned_directory_rejects_a_leaf_replacement_after_open(self) -> None:
        import os
        import sandbox_store
        from sandbox_store import PinnedDirectory, SandboxStoreError

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            task_dir = root / "T-001"
            self._write_scope(task_dir)
            original_stat = sandbox_store.os.stat
            leaf_stats = []

            def changed_leaf_stat(path, *args, **kwargs):
                if path == "scope.json" and kwargs.get("dir_fd") is not None:
                    current = original_stat(path, *args, **kwargs)
                    leaf_stats.append(current)
                    if len(leaf_stats) == 2:
                        values = list(current)
                        values[1] = int(values[1]) + 1
                        return os.stat_result(values)
                    return current
                return original_stat(path, *args, **kwargs)

            with PinnedDirectory(root, task_dir) as directory, mock.patch.object(
                sandbox_store.os, "stat", side_effect=changed_leaf_stat
            ):
                with self.assertRaisesRegex(SandboxStoreError, "^sandbox_scope_changed$"):
                    directory.read_bytes("scope.json", max_bytes=1024, label="sandbox_scope")

    def test_task_manager_default_runner_blocks_before_subprocess_execution(self) -> None:
        from task_router import TaskManager

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = TaskManager(root / "tasks.jsonl", root / "runs")
            with mock.patch("task_router.subprocess.Popen", side_effect=AssertionError("subprocess_must_not_run")):
                task = manager.submit(
                    "https://example.test",
                    "/goal 测试 https://example.test",
                    goal_id="G-DEFAULT-BLOCKED",
                    profile_name="standard-pentest",
                    target_id="example-target",
                    target_card_digest="a" * 64,
                    idempotency_key="G-DEFAULT-BLOCKED",
                )
                for _ in range(100):
                    current = {item["id"]: item for item in manager.list_tasks()}[task["id"]]
                    if current["status"] != "running":
                        break
                    time.sleep(0.02)
            current = {item["id"]: item for item in manager.list_tasks()}[task["id"]]
            self.assertEqual("blocked", current["status"])
            self.assertEqual(125, current["exit_code"])

    def test_task_manager_does_not_persist_runner_exception_text(self) -> None:
        from task_router import TaskManager

        def leaking_runner(*_args) -> int:
            raise RuntimeError("RUNNER_SECRET_SENTINEL")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = TaskManager(root / "tasks.jsonl", root / "runs", runner=leaking_runner)
            task = manager.submit(
                "https://example.test",
                "/goal 测试 https://example.test",
                goal_id="G-SANITIZE-RUNNER",
                profile_name="standard-pentest",
                target_id="example-target",
                target_card_digest="a" * 64,
                idempotency_key="G-SANITIZE-RUNNER",
            )
            for _ in range(100):
                current = {item["id"]: item for item in manager.list_tasks()}[task["id"]]
                if current["status"] != "running":
                    break
                time.sleep(0.02)
            log_text = (Path(task["output_path"]) / "strix.log").read_text(encoding="utf-8")
            tasks_text = (root / "tasks.jsonl").read_text(encoding="utf-8")
            self.assertNotIn("RUNNER_SECRET_SENTINEL", log_text)
            self.assertNotIn("RUNNER_SECRET_SENTINEL", tasks_text)

    def test_task_manager_does_not_mislabel_an_arbitrary_125_exit_as_blocked(self) -> None:
        from task_router import TaskManager

        side_effect = []

        def runner(*_args) -> int:
            side_effect.append("executed")
            return 125

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = TaskManager(root / "tasks.jsonl", root / "runs", runner=runner)
            task = manager.submit(
                "https://example.test",
                "/goal 测试 https://example.test",
                goal_id="G-ARBITRARY-125",
                profile_name="standard-pentest",
                target_id="example-target",
                target_card_digest="a" * 64,
                idempotency_key="G-ARBITRARY-125",
            )
            for _ in range(100):
                current = {item["id"]: item for item in manager.list_tasks()}[task["id"]]
                if current["status"] != "running":
                    break
                time.sleep(0.02)
            current = {item["id"]: item for item in manager.list_tasks()}[task["id"]]
            self.assertEqual(["executed"], side_effect)
            self.assertEqual("failed", current["status"])

    def test_task_manager_sanitizes_a_runner_block_reason(self) -> None:
        from runner_contract import RunnerBlockedError
        from task_router import TaskManager

        def blocked_runner(*_args) -> int:
            raise RunnerBlockedError("RUNNER_SECRET_SENTINEL")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = TaskManager(root / "tasks.jsonl", root / "runs", runner=blocked_runner)
            task = manager.submit(
                "https://example.test",
                "/goal 测试 https://example.test",
                goal_id="G-BLOCKED-SANITIZE",
                profile_name="standard-pentest",
                target_id="example-target",
                target_card_digest="a" * 64,
                idempotency_key="G-BLOCKED-SANITIZE",
            )
            for _ in range(100):
                current = {item["id"]: item for item in manager.list_tasks()}[task["id"]]
                if current["status"] != "running":
                    break
                time.sleep(0.02)
            log_text = (Path(task["output_path"]) / "strix.log").read_text(encoding="utf-8")
            tasks_text = (root / "tasks.jsonl").read_text(encoding="utf-8")
            self.assertEqual("blocked", current["status"])
            self.assertNotIn("RUNNER_SECRET_SENTINEL", log_text)
            self.assertNotIn("RUNNER_SECRET_SENTINEL", tasks_text)

    def test_task_manager_finalizes_when_writing_the_runner_log_fails(self) -> None:
        from runner_contract import RunnerBlockedError
        from task_router import TaskManager

        def blocked_runner(_command, _cwd, _env, log_path, _timeout) -> int:
            log_path.mkdir()
            raise RunnerBlockedError("synthetic_no_execution")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = TaskManager(root / "tasks.jsonl", root / "runs", runner=blocked_runner)
            task = manager.submit(
                "https://example.test",
                "/goal 测试 https://example.test",
                goal_id="G-LOG-WRITE-FAILURE",
                profile_name="standard-pentest",
                target_id="example-target",
                target_card_digest="a" * 64,
                idempotency_key="G-LOG-WRITE-FAILURE",
            )
            for _ in range(100):
                current = {item["id"]: item for item in manager.list_tasks()}[task["id"]]
                if current["status"] != "running":
                    break
                time.sleep(0.02)

            current = {item["id"]: item for item in manager.list_tasks()}[task["id"]]
            self.assertEqual("blocked", current["status"])
            self.assertEqual("write_failed", current["runner_log_state"])
            self.assertIsNone(manager._running)

    def test_task_manager_records_the_injected_synthetic_runner_as_blocked(self) -> None:
        from quarantine_importer import QuarantineImporter
        from task_router import TaskManager
        from tool_runner import SyntheticToolRunner

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_root = root / "sources"
            source_root.mkdir()
            source, sentinel = self._write_source(source_root)
            receipt = QuarantineImporter(source_root).inspect(source)
            runs_root = root / "runs"
            runner = self._runner(source_root, source, receipt, runs_root)
            manager = TaskManager(root / "tasks.jsonl", runs_root, runner=runner, strix_bin=str(source))
            task = manager.submit(
                "https://example.test",
                "/goal 测试 https://example.test",
                goal_id="G-TOOL-001",
                profile_name="standard-pentest",
                target_id="example-target",
                target_card_digest="a" * 64,
                idempotency_key="G-TOOL-001",
            )
            for _ in range(100):
                current = {item["id"]: item for item in manager.list_tasks()}[task["id"]]
                if current["status"] != "running":
                    break
                time.sleep(0.02)
            current = {item["id"]: item for item in manager.list_tasks()}[task["id"]]
            card_path = Path(task["output_path"]) / "quarantine" / task["run_id"] / "sandbox-run.json"
            self.assertEqual("blocked", current["status"])
            self.assertEqual(125, current["exit_code"])
            self.assertTrue(card_path.is_file())
            self.assertFalse(sentinel.exists())


if __name__ == "__main__":
    unittest.main()
