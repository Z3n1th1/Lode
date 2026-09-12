"""Regression contract for the canonical Strix task submission adapter."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch


PENTEST_AGENT = Path(__file__).resolve().parents[1]
for directory in (PENTEST_AGENT / "core", PENTEST_AGENT / "notify"):
    sys.path.insert(0, str(directory))


def _bound_pairs(target_card_digest: str = "a" * 64) -> dict:
    return {
        "PAIR-001": {
            "pair_id": "PAIR-001",
            "target_id": "example-target",
            "target_card_digest": target_card_digest,
        }
    }


class TaskRouterIdempotencyTests(unittest.TestCase):
    def test_new_task_requires_a_canonical_target_identity(self) -> None:
        from task_router import TaskManager

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = TaskManager(root / "tasks.jsonl", root / "runs", runner=lambda *args, **kwargs: 0)
            with self.assertRaisesRegex(ValueError, "^target_identity_binding_required$"):
                manager.submit(
                    "https://example.test",
                    "confirmed target intake",
                    goal_id="G-IDENTITY-REQUIRED",
                    profile_name="standard-pentest",
                    idempotency_key="G-IDENTITY-REQUIRED",
                )

    def test_target_card_digest_is_persisted_and_bound_into_task_evidence(self) -> None:
        from task_router import TaskManager

        digest = "a" * 64
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = TaskManager(root / "tasks.jsonl", root / "runs", runner=lambda *args, **kwargs: 0)
            task = manager.submit(
                "https://example.test",
                "confirmed target intake",
                goal_id="G-INTAKE-001",
                profile_name="standard-pentest",
                target_id="example-target",
                target_card_digest=digest,
                idempotency_key="G-INTAKE-001",
            )
            for _ in range(100):
                if manager.list_tasks()[0]["status"] != "running":
                    break
                time.sleep(0.02)

            binding = json.loads(
                (Path(task["output_path"]) / "evidence" / "task_binding.json").read_text(encoding="utf-8")
            )
            self.assertEqual(digest, task["target_card_digest"])
            self.assertEqual(digest, binding["target_card_digest"])
            TaskManager._validate_task_evidence_binding(task, Path(task["output_path"]))

    def test_same_task_idempotency_key_rejects_target_card_digest_drift(self) -> None:
        from task_router import TaskManager

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = TaskManager(root / "tasks.jsonl", root / "runs", runner=lambda *args, **kwargs: 0)
            task = manager.submit(
                "https://example.test",
                "confirmed target intake",
                goal_id="G-INTAKE-002",
                profile_name="standard-pentest",
                target_id="example-target",
                target_card_digest="a" * 64,
                idempotency_key="G-INTAKE-002",
            )
            for _ in range(100):
                if manager.list_tasks()[0]["status"] != "running":
                    break
                time.sleep(0.02)
            self.assertEqual("finished", manager.list_tasks()[0]["status"])
            with self.assertRaisesRegex(ValueError, "^idempotency_key_conflict:G-INTAKE-002$"):
                manager.submit(
                    "https://example.test",
                    "confirmed target intake",
                goal_id="G-INTAKE-002",
                profile_name="standard-pentest",
                target_id="example-target",
                target_card_digest="b" * 64,
                    idempotency_key="G-INTAKE-002",
                )

    def test_target_card_bound_task_requires_the_matching_verifier_target_id(self) -> None:
        from task_router import TaskManager

        def resolver(task, _evidence_dir):
            return {
                "finding": {
                    "finding_id": "F-TARGET-BIND",
                    "title": "synthetic verified finding",
                    "detail": "",
                    "type": "vertical_idor",
                    "severity": "high",
                    "evidence_level": "L3_reproducible_impact",
                },
                "verifier": {
                    "schema": "VerifierResult/v1",
                    "run_id": task["run_id"],
                    "target_id": "foreign-target",
                    "finding_id": "F-TARGET-BIND",
                    "status": "confirmed",
                    "recommend_report": True,
                    "verification_mode": "independent_agent",
                    "verification_origin": "separate_agent",
                    "verifier_id": "verifier-worker-1",
                    "integrity_status": "pass",
                    "evidence_pair_count": 1,
                    "evidence_pair_ids": ["PAIR-001"],
                    "impact_assertion_digest": "d" * 64,
                    "worker_attestation_digest": "e" * 64,
                    "record_digest": "f" * 64,
                    "input_manifest_digest": "b" * 64,
                },
                "pairs": _bound_pairs(),
            }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = TaskManager(root / "tasks.jsonl", root / "runs", runner=lambda *args, **kwargs: 0)
            task = manager.submit(
                "https://example.test",
                "confirmed target intake",
                goal_id="G-INTAKE-003",
                profile_name="standard-pentest",
                target_id="example-target",
                target_card_digest="a" * 64,
                idempotency_key="G-INTAKE-003",
            )
            for _ in range(100):
                if manager.list_tasks()[0]["status"] != "running":
                    break
                time.sleep(0.02)
            evidence_dir = Path(task["output_path"]) / "evidence" / "F-TARGET-BIND"
            evidence_dir.mkdir(parents=True)

            with patch("task_router.TaskManager._resolve_canonical_verified_finding", side_effect=resolver):
                with self.assertRaisesRegex(ValueError, "^canonical_target_identity_mismatch$"):
                    manager.publish_verified_finding(task["id"], evidence_dir)

    def test_target_card_bound_task_rejects_a_canonical_pair_with_a_different_card_digest(self) -> None:
        from task_router import TaskManager

        task_digest = "a" * 64

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = TaskManager(root / "tasks.jsonl", root / "runs", runner=lambda *args, **kwargs: 0)
            task = manager.submit(
                "https://example.test",
                "confirmed target intake",
                goal_id="G-INTAKE-PAIR",
                profile_name="standard-pentest",
                target_id="example-target",
                target_card_digest=task_digest,
                idempotency_key="G-INTAKE-PAIR",
            )
            for _ in range(100):
                if manager.list_tasks()[0]["status"] != "running":
                    break
                time.sleep(0.02)
            evidence_dir = Path(task["output_path"]) / "evidence" / "F-TARGET-PAIR"
            evidence_dir.mkdir(parents=True)

            verifier = {
                "schema": "VerifierResult/v1",
                "run_id": task["run_id"],
                "target_id": "example-target",
                "finding_id": "F-TARGET-PAIR",
                "status": "confirmed",
                "recommend_report": True,
                "verification_mode": "independent_agent",
                "verification_origin": "separate_agent",
                "verifier_id": "verifier-worker-1",
                "integrity_status": "pass",
                "evidence_pair_count": 1,
                "evidence_pair_ids": ["PAIR-001"],
                "impact_assertion_digest": "d" * 64,
                "worker_attestation_digest": "e" * 64,
                "record_digest": "f" * 64,
                "input_manifest_digest": "b" * 64,
            }
            resolved = {
                "finding": {
                    "finding_id": "F-TARGET-PAIR",
                    "title": "synthetic verified finding",
                    "detail": "",
                    "type": "vertical_idor",
                    "severity": "high",
                    "evidence_level": "L3_reproducible_impact",
                },
                "verifier": verifier,
                "pairs": {
                    "PAIR-001": {
                        "pair_id": "PAIR-001",
                        "target_id": "example-target",
                        "target_card_digest": "b" * 64,
                    }
                },
            }

            with patch(
                "task_router.TaskManager._resolve_canonical_verified_finding", return_value=resolved
            ):
                with self.assertRaisesRegex(ValueError, "^canonical_target_pair_digest_mismatch$"):
                    manager.publish_verified_finding(task["id"], evidence_dir)

    def test_replayed_goal_returns_the_same_persisted_task_without_a_second_run(self) -> None:
        from task_router import TaskManager

        runner_calls = []

        def fake_runner(command, cwd, env, log_path, timeout):
            runner_calls.append(command)
            report_dir = Path(cwd) / "strix_runs" / "run-1"
            report_dir.mkdir(parents=True)
            (report_dir / "penetration_test_report.md").write_text("# synthetic report", encoding="utf-8")
            Path(log_path).write_text("synthetic", encoding="utf-8")
            return 0

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tasks_path = root / "tasks.jsonl"
            manager = TaskManager(tasks_path, root / "runs", runner=fake_runner)
            first = manager.submit(
                "https://example.test",
                "/goal 测试 https://example.test",
                user_id="u1",
                chat_id="c1",
                goal_id="G-001",
                profile_name="standard-pentest",
                target_id="example-target",
                target_card_digest="a" * 64,
                idempotency_key="G-001",
            )
            for _ in range(50):
                if manager.list_tasks()[0]["status"] != "running":
                    break
                time.sleep(0.02)
            self.assertNotEqual("running", manager.list_tasks()[0]["status"])
            restored = TaskManager(tasks_path, root / "runs", runner=fake_runner)
            replay = restored.submit(
                "https://example.test",
                "/goal 测试 https://example.test",
                user_id="u1",
                chat_id="c1",
                goal_id="G-001",
                profile_name="standard-pentest",
                target_id="example-target",
                target_card_digest="a" * 64,
                idempotency_key="G-001",
            )

            self.assertEqual(first["id"], replay["id"])
            self.assertEqual(1, len(runner_calls))
            scope = json.loads((Path(first["output_path"]) / "scope.json").read_text(encoding="utf-8"))
            self.assertEqual("G-001", scope["goal_id"])
            self.assertEqual("standard-pentest", scope["profile_name"])
            self.assertEqual("G-001", scope["idempotency_key"])

    def test_completion_notification_does_not_expose_a_local_report_path(self) -> None:
        from task_router import TaskManager

        notifications = []

        def runner(command, cwd, env, log_path, timeout):
            report_dir = Path(cwd) / "strix_runs" / "run-1"
            report_dir.mkdir(parents=True)
            (report_dir / "penetration_test_report.md").write_text("# synthetic report", encoding="utf-8")
            return 0

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = TaskManager(
                root / "tasks.jsonl",
                root / "runs",
                runner=runner,
                notify_fn=lambda chat_id, text: notifications.append((chat_id, text)),
            )
            task = manager.submit(
                "https://example.test",
                "/goal 测试 https://example.test",
                chat_id="oc_test",
                goal_id="G-003",
                profile_name="standard-pentest",
                target_id="example-target",
                target_card_digest="a" * 64,
                idempotency_key="G-003",
            )
            for _ in range(100):
                if notifications:
                    break
                time.sleep(0.02)

        self.assertEqual(1, len(notifications))
        self.assertEqual("oc_test", notifications[0][0])
        self.assertIn("回复 1", notifications[0][1])
        self.assertNotIn(str(Path(task["output_path"]) / "strix_runs"), notifications[0][1])

    def test_lifecycle_events_emit_once_for_a_new_task_but_not_for_a_replay(self) -> None:
        from task_router import TaskManager

        events = []

        def runner(command, cwd, env, log_path, timeout):
            return 0

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = TaskManager(
                root / "tasks.jsonl",
                root / "runs",
                runner=runner,
                event_fn=lambda kind, task: events.append((kind, task["id"])),
            )
            task = manager.submit(
                "https://example.test",
                "/goal 测试 https://example.test",
                goal_id="G-004",
                profile_name="standard-pentest",
                target_id="example-target",
                target_card_digest="a" * 64,
                idempotency_key="G-004",
            )
            for _ in range(100):
                if len(events) == 2:
                    break
                time.sleep(0.02)
            replay = TaskManager(
                root / "tasks.jsonl",
                root / "runs",
                runner=runner,
                event_fn=lambda kind, replay_task: events.append((kind, replay_task["id"])),
            ).submit(
                "https://example.test",
                "/goal 测试 https://example.test",
                goal_id="G-004",
                profile_name="standard-pentest",
                target_id="example-target",
                target_card_digest="a" * 64,
                idempotency_key="G-004",
            )

        self.assertEqual(task["id"], replay["id"])
        self.assertEqual([("started", "T-001"), ("finished", "T-001")], events)

    def test_blocked_event_delivery_does_not_delay_task_submission(self) -> None:
        from task_router import TaskManager

        callback_started = threading.Event()
        release_callback = threading.Event()
        events = []

        def event_fn(kind, task):
            if kind == "started":
                callback_started.set()
                release_callback.wait(0.35)
            events.append((kind, task["id"]))

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = TaskManager(
                root / "tasks.jsonl",
                root / "runs",
                runner=lambda *args, **kwargs: 0,
                event_fn=event_fn,
            )
            submitted_at = time.monotonic()
            task = manager.submit(
                "https://example.test",
                "/goal 测试 https://example.test",
                goal_id="G-004A",
                profile_name="standard-pentest",
                target_id="example-target",
                target_card_digest="a" * 64,
                idempotency_key="G-004A",
            )
            elapsed = time.monotonic() - submitted_at
            try:
                self.assertTrue(callback_started.wait(0.2))
                self.assertLess(elapsed, 0.15)
            finally:
                release_callback.set()
                for _ in range(100):
                    if len(events) == 2:
                        break
                    time.sleep(0.02)

        self.assertEqual([("started", task["id"]), ("finished", task["id"])], events)

    def test_running_task_emits_a_truthful_periodic_progress_event(self) -> None:
        from task_router import TaskManager

        events = []

        def runner(command, cwd, env, log_path, timeout):
            time.sleep(0.06)
            return 0

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = TaskManager(
                root / "tasks.jsonl",
                root / "runs",
                runner=runner,
                event_fn=lambda kind, task: events.append((kind, task)),
                progress_interval=0.01,
            )
            task = manager.submit(
                "https://example.test",
                "/goal 测试 https://example.test",
                goal_id="G-004B",
                profile_name="standard-pentest",
                target_id="example-target",
                target_card_digest="a" * 64,
                idempotency_key="G-004B",
            )
            for _ in range(100):
                if any(kind == "finished" for kind, _ in events):
                    break
                time.sleep(0.02)

        progress = [event for kind, event in events if kind == "progress"]
        self.assertTrue(progress)
        self.assertTrue(all(event["id"] == task["id"] for event in progress))
        self.assertTrue(all(event["elapsed_seconds"] > 0 for event in progress))
        self.assertTrue(all("audited" not in event and "total" not in event for event in progress))

    def test_terminal_event_is_last_after_periodic_progress(self) -> None:
        from task_router import TaskManager

        events = []

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = TaskManager(
                root / "tasks.jsonl",
                root / "runs",
                runner=lambda *args, **kwargs: time.sleep(0.06) or 0,
                event_fn=lambda kind, task: events.append(kind),
                progress_interval=0.01,
            )
            manager.submit(
                "https://example.test",
                "/goal 测试 https://example.test",
                goal_id="G-004B2",
                profile_name="standard-pentest",
                target_id="example-target",
                target_card_digest="a" * 64,
                idempotency_key="G-004B2",
            )
            for _ in range(100):
                if "finished" in events:
                    break
                time.sleep(0.02)
            time.sleep(0.04)

        self.assertIn("progress", events)
        self.assertEqual("finished", events[-1])

    def test_confirmed_finding_is_persisted_before_its_broadcast_event(self) -> None:
        from task_router import TaskManager

        broadcasts = []
        resolver_calls = []
        # publish_verified_finding() resolves twice per attempt: once before and
        # once inside the final task lock. Keep each attempt internally stable,
        # then change the verifier receipt for the second publish attempt.
        resolver_digests = [
            "a" * 64,
            "a" * 64,
            "a" * 64,
            "a" * 64,
            "c" * 64,
            "c" * 64,
        ]

        def verifier_resolver(task, evidence_dir):
            digest = resolver_digests[min(len(resolver_calls), len(resolver_digests) - 1)]
            resolver_calls.append((task, evidence_dir))
            return {
                "finding": {
                    "finding_id": "F-001",
                    "title": "已验证垂直越权",
                    "detail": "低权限账号读取管理资源",
                    "type": "vertical_idor",
                    "severity": "high",
                    "evidence_level": "L3_reproducible_impact",
                },
                "verifier": {
                    "schema": "VerifierResult/v1",
                    "run_id": task["run_id"],
                    "target_id": "example-target",
                    "finding_id": "F-001",
                    "status": "confirmed",
                    "recommend_report": True,
                    "verification_mode": "independent_agent",
                    "verification_origin": "separate_agent",
                    "verifier_id": "verifier-worker-1",
                    "integrity_status": "pass",
                    "evidence_pair_count": 1,
                    "evidence_pair_ids": ["PAIR-001"],
                    "impact_assertion_digest": "d" * 64,
                    "worker_attestation_digest": "e" * 64,
                    "record_digest": digest,
                    "input_manifest_digest": "b" * 64,
                },
                "pairs": _bound_pairs(),
            }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = TaskManager(
                root / "tasks.jsonl",
                root / "runs",
                runner=lambda *args, **kwargs: 0,
                event_fn=lambda kind, task: broadcasts.append((kind, task)),
            )
            task = manager.submit(
                "https://example.test",
                "/goal 测试 https://example.test",
                goal_id="G-004C",
                profile_name="standard-pentest",
                target_id="example-target",
                target_card_digest="a" * 64,
                idempotency_key="G-004C",
            )
            for _ in range(100):
                if manager.list_tasks()[0]["status"] == "finished":
                    break
                time.sleep(0.02)

            evidence_dir = Path(task["output_path"]) / "evidence" / "F-001"
            evidence_dir.mkdir(parents=True)
            with patch("task_router.TaskManager._resolve_canonical_verified_finding", side_effect=verifier_resolver), patch(
                "task_router.os.fsync"
            ) as fsync:
                published = manager.publish_verified_finding(task["id"], evidence_dir)
                duplicate = manager.publish_verified_finding(task["id"], evidence_dir)
                with self.assertRaisesRegex(ValueError, "^verified_finding_provenance_conflict$"):
                    manager.publish_verified_finding(task["id"], evidence_dir)
            for _ in range(100):
                if any(kind == "verified_finding" for kind, _ in broadcasts):
                    break
                time.sleep(0.02)

            ledger = Path(task["output_path"]) / "verified_findings.jsonl"
            entries = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines()]

        self.assertGreaterEqual(fsync.call_count, 1)
        self.assertFalse(published["duplicate"])
        self.assertTrue(duplicate["duplicate"])
        self.assertEqual(1, len(entries))
        self.assertEqual("TaskVerifiedFinding/v1", entries[0]["schema"])
        self.assertEqual("target_card", entries[0]["target_identity_binding"])
        self.assertEqual("TaskVerifierProvenance/v1", entries[0]["verifier"]["schema"])
        self.assertEqual("https://example.test", entries[0]["task_target"])
        self.assertEqual("confirmed", entries[0]["finding"]["verifier_status"])
        self.assertEqual("a" * 64, entries[0]["verifier"]["record_digest"])
        self.assertEqual("b" * 64, entries[0]["verifier"]["input_manifest_digest"])
        self.assertEqual(task["run_id"], entries[0]["verifier"]["run_id"])
        self.assertEqual("example-target", entries[0]["verifier"]["target_id"])
        self.assertEqual("target_card", entries[0]["verifier"].get("target_id_binding"))
        self.assertEqual("pass", entries[0]["verifier"]["integrity_status"])
        self.assertEqual(1, entries[0]["verifier"]["evidence_pair_count"])
        self.assertRegex(entries[0]["verifier"].get("evidence_pair_ids_digest", ""), r"^[0-9a-f]{64}$")
        self.assertNotIn("evidence_pair_ids", entries[0]["verifier"])
        self.assertEqual(6, len(resolver_calls))
        self.assertEqual("https://example.test", resolver_calls[0][0]["target"])
        self.assertEqual(evidence_dir, resolver_calls[0][1])
        finding_events = [event for kind, event in broadcasts if kind == "verified_finding"]
        self.assertEqual(1, len(finding_events))
        self.assertEqual("F-001", finding_events[0]["finding"]["finding_id"])

    def test_canonical_resolver_accepts_schema_valid_finding_without_legacy_task_binding(self) -> None:
        """Task binding is a TaskRouter sidecar, not an EvidenceCard field."""
        from task_router import TaskManager
        import types

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = TaskManager(root / "tasks.jsonl", root / "runs", runner=lambda *args, **kwargs: 0)
            task = manager.submit(
                "https://example.test",
                "/goal 测试 https://example.test",
                goal_id="G-004C1",
                profile_name="standard-pentest",
                target_id="example-target",
                target_card_digest="a" * 64,
                idempotency_key="G-004C1",
            )
            for _ in range(100):
                if manager.list_tasks()[0]["status"] == "finished":
                    break
                time.sleep(0.02)

            evidence_dir = Path(task["output_path"]) / "evidence" / "F-001"
            evidence_dir.mkdir(parents=True)
            verifier = {
                "finding_id": "F-001",
                "run_id": task["run_id"],
                "input_manifest_digest": "a" * 64,
            }
            fake_trust_chain = types.SimpleNamespace(
                validate_verifier_result=lambda *args, **kwargs: {
                    "ok": True,
                    "record": verifier,
                    "manifest": {"digest": "a" * 64},
                },
            )
            guardrails_root = PENTEST_AGENT / "guardrails-mcp"
            if str(guardrails_root) not in sys.path:
                sys.path.insert(0, str(guardrails_root))
            from guardrails import scripts_bridge
            try:
                from schema_validator import load_default_contracts, validate_doc
            except ModuleNotFoundError:
                self.skipTest("private ai-pentest-matrix schema contracts are not packaged")

            evidence_card = {
                "schema": "EvidenceCard/v1",
                "finding_id": "F-001",
                "target_id": "example-target",
                "evidence": {
                    "requests": ["evidence/F-001/requests/001.req"],
                    "responses": ["evidence/F-001/responses/001.resp"],
                    "screenshots": [],
                },
            }
            self.assertEqual([], validate_doc(evidence_card, load_default_contracts()))

            resolver_task = {
                "id": task["id"],
                "target": task["target"],
                "run_id": task["run_id"],
                "output_path": task["output_path"],
            }
            with patch.object(scripts_bridge, "scripts_available", return_value=True), patch.dict(
                sys.modules, {"trust_chain": fake_trust_chain}
            ):
                resolved = TaskManager._resolve_canonical_verified_finding(resolver_task, evidence_dir)
                verifier["run_id"] = "foreign-run"
                with self.assertRaisesRegex(ValueError, "^canonical_task_binding_missing$"):
                    TaskManager._resolve_canonical_verified_finding(resolver_task, evidence_dir)
                verifier["run_id"] = task["run_id"]
                verifier["input_manifest_digest"] = "b" * 64
                with self.assertRaisesRegex(ValueError, "^canonical_task_binding_missing$"):
                    TaskManager._resolve_canonical_verified_finding(resolver_task, evidence_dir)

        self.assertEqual("F-001", resolved["finding"]["finding_id"])
        self.assertEqual(task["run_id"], resolved["verifier"]["run_id"])

    def test_verified_finding_rejects_receipt_change_between_canonical_checks(self) -> None:
        from task_router import TaskManager

        resolver_digests = ["a" * 64, "c" * 64]

        def resolver(task, evidence_dir):
            digest = resolver_digests.pop(0)
            return {
                "finding": {
                    "finding_id": "F-001",
                    "title": "已验证垂直越权",
                    "detail": "低权限账号读取管理资源",
                    "type": "vertical_idor",
                    "severity": "high",
                    "evidence_level": "L3_reproducible_impact",
                },
                "verifier": {
                    "schema": "VerifierResult/v1",
                    "run_id": task["run_id"],
                    "target_id": "example-target",
                    "finding_id": "F-001",
                    "status": "confirmed",
                    "recommend_report": True,
                    "verification_mode": "independent_agent",
                    "verification_origin": "separate_agent",
                    "verifier_id": "verifier-worker-1",
                    "integrity_status": "pass",
                    "evidence_pair_count": 1,
                    "evidence_pair_ids": ["PAIR-001"],
                    "impact_assertion_digest": "d" * 64,
                    "worker_attestation_digest": "e" * 64,
                    "record_digest": digest,
                    "input_manifest_digest": "b" * 64,
                },
                "pairs": _bound_pairs(),
            }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = TaskManager(root / "tasks.jsonl", root / "runs", runner=lambda *args, **kwargs: 0)
            task = manager.submit(
                "https://example.test",
                "/goal 测试 https://example.test",
                goal_id="G-004C1A",
                profile_name="standard-pentest",
                target_id="example-target",
                target_card_digest="a" * 64,
                idempotency_key="G-004C1A",
            )
            for _ in range(100):
                if manager.list_tasks()[0]["status"] == "finished":
                    break
                time.sleep(0.02)
            evidence_dir = Path(task["output_path"]) / "evidence" / "F-001"
            evidence_dir.mkdir(parents=True)

            with patch("task_router.TaskManager._resolve_canonical_verified_finding", side_effect=resolver):
                with self.assertRaisesRegex(ValueError, "^canonical_verifier_changed_during_publish$"):
                    manager.publish_verified_finding(task["id"], evidence_dir)

            self.assertFalse((Path(task["output_path"]) / "verified_findings.jsonl").exists())

    def test_verified_finding_holds_the_canonical_evidence_writer_lock(self) -> None:
        from task_router import TaskManager

        class TrackingLock:
            entered = False
            exited = False

            def __enter__(self):
                self.entered = True
                return self

            def __exit__(self, exc_type, exc_value, traceback):
                self.exited = True
                return False

        lock = TrackingLock()

        def resolver(task, evidence_dir):
            self.assertTrue(lock.entered)
            return {
                "finding": {
                    "finding_id": "F-001",
                    "title": "已验证垂直越权",
                    "detail": "低权限账号读取管理资源",
                    "type": "vertical_idor",
                    "severity": "high",
                    "evidence_level": "L3_reproducible_impact",
                },
                "verifier": {
                    "schema": "VerifierResult/v1",
                    "run_id": task["run_id"],
                    "target_id": "example-target",
                    "finding_id": "F-001",
                    "status": "confirmed",
                    "recommend_report": True,
                    "verification_mode": "independent_agent",
                    "verification_origin": "separate_agent",
                    "verifier_id": "verifier-worker-1",
                    "integrity_status": "pass",
                    "evidence_pair_count": 1,
                    "evidence_pair_ids": ["PAIR-001"],
                    "impact_assertion_digest": "d" * 64,
                    "worker_attestation_digest": "e" * 64,
                    "record_digest": "a" * 64,
                    "input_manifest_digest": "b" * 64,
                },
                "pairs": _bound_pairs(),
            }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = TaskManager(root / "tasks.jsonl", root / "runs", runner=lambda *args, **kwargs: 0)
            task = manager.submit(
                "https://example.test",
                "/goal 测试 https://example.test",
                goal_id="G-004C1B",
                profile_name="standard-pentest",
                target_id="example-target",
                target_card_digest="a" * 64,
                idempotency_key="G-004C1B",
            )
            for _ in range(100):
                if manager.list_tasks()[0]["status"] == "finished":
                    break
                time.sleep(0.02)
            evidence_dir = Path(task["output_path"]) / "evidence" / "F-001"
            evidence_dir.mkdir(parents=True)

            with patch.object(TaskManager, "_canonical_evidence_lock", return_value=lock, create=True), patch(
                "task_router.TaskManager._resolve_canonical_verified_finding", side_effect=resolver
            ):
                result = manager.publish_verified_finding(task["id"], evidence_dir)

        self.assertFalse(result["duplicate"])
        self.assertTrue(lock.entered)
        self.assertTrue(lock.exited)

    def test_verified_finding_revalidates_task_binding_after_resolver_returns(self) -> None:
        from task_router import TaskManager

        def resolver(task, evidence_dir):
            binding_path = Path(task["output_path"]) / "evidence" / "task_binding.json"
            binding = json.loads(binding_path.read_text(encoding="utf-8"))
            binding["run_id"] = "tampered-run"
            binding_path.write_text(json.dumps(binding), encoding="utf-8")
            return {
                "finding": {
                    "finding_id": "F-001",
                    "title": "已验证垂直越权",
                    "detail": "低权限账号读取管理资源",
                    "type": "vertical_idor",
                    "severity": "high",
                    "evidence_level": "L3_reproducible_impact",
                },
                "verifier": {
                    "schema": "VerifierResult/v1",
                    "run_id": task["run_id"],
                    "target_id": "example-target",
                    "finding_id": "F-001",
                    "status": "confirmed",
                    "recommend_report": True,
                    "verification_mode": "independent_agent",
                    "verification_origin": "separate_agent",
                    "verifier_id": "verifier-worker-1",
                    "integrity_status": "pass",
                    "evidence_pair_count": 1,
                    "evidence_pair_ids": ["PAIR-001"],
                    "impact_assertion_digest": "d" * 64,
                    "worker_attestation_digest": "e" * 64,
                    "record_digest": "a" * 64,
                    "input_manifest_digest": "b" * 64,
                },
                "pairs": _bound_pairs(),
            }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = TaskManager(root / "tasks.jsonl", root / "runs", runner=lambda *args, **kwargs: 0)
            task = manager.submit(
                "https://example.test",
                "/goal 测试 https://example.test",
                goal_id="G-004C2",
                profile_name="standard-pentest",
                target_id="example-target",
                target_card_digest="a" * 64,
                idempotency_key="G-004C2",
            )
            for _ in range(100):
                if manager.list_tasks()[0]["status"] == "finished":
                    break
                time.sleep(0.02)
            evidence_dir = Path(task["output_path"]) / "evidence" / "F-001"
            evidence_dir.mkdir(parents=True)

            with patch("task_router.TaskManager._resolve_canonical_verified_finding", side_effect=resolver):
                with self.assertRaisesRegex(ValueError, "^task_evidence_binding_invalid$"):
                    manager.publish_verified_finding(task["id"], evidence_dir)

            ledger_path = Path(task["output_path"]) / "verified_findings.jsonl"
            self.assertFalse(ledger_path.exists())

    def test_verified_finding_rejects_evidence_outside_its_task_directory(self) -> None:
        from task_router import TaskManager

        resolver_calls = []
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = TaskManager(
                root / "tasks.jsonl",
                root / "runs",
                runner=lambda *args, **kwargs: 0,
            )
            task = manager.submit(
                "https://example.test",
                "/goal 测试 https://example.test",
                goal_id="G-004D",
                profile_name="standard-pentest",
                target_id="example-target",
                target_card_digest="a" * 64,
                idempotency_key="G-004D",
            )
            for _ in range(100):
                if manager.list_tasks()[0]["status"] == "finished":
                    break
                time.sleep(0.02)
            foreign_evidence = root / "foreign-evidence"
            foreign_evidence.mkdir()

            with patch(
                "task_router.TaskManager._resolve_canonical_verified_finding",
                side_effect=lambda task, evidence_dir: resolver_calls.append((task, evidence_dir)),
            ):
                with self.assertRaisesRegex(ValueError, "^evidence_dir_outside_task$"):
                    manager.publish_verified_finding(task["id"], foreign_evidence)

        self.assertEqual([], resolver_calls)

    def test_task_evidence_binding_detects_target_or_scope_drift(self) -> None:
        from task_router import TaskManager

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = TaskManager(
                root / "tasks.jsonl",
                root / "runs",
                runner=lambda *args, **kwargs: 0,
            )
            task = manager.submit(
                "https://example.test",
                "/goal 测试 https://example.test",
                goal_id="G-004E",
                profile_name="standard-pentest",
                target_id="example-target",
                target_card_digest="a" * 64,
                idempotency_key="G-004E",
            )
            for _ in range(100):
                if manager.list_tasks()[0]["status"] == "finished":
                    break
                time.sleep(0.02)
            task_dir = Path(task["output_path"])
            binding_path = task_dir / "evidence" / "task_binding.json"
            binding = json.loads(binding_path.read_text(encoding="utf-8"))
            self.assertEqual(task["id"], binding["task_id"])
            self.assertEqual("https://example.test", binding["target"])
            self.assertEqual(task["run_id"], binding["run_id"])
            TaskManager._validate_task_evidence_binding(task, task_dir)

            binding["target"] = "https://other.example.test"
            binding_path.write_text(json.dumps(binding), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "^task_evidence_binding_invalid$"):
                TaskManager._validate_task_evidence_binding(task, task_dir)

    def test_task_evidence_binding_rejects_scope_and_hash_rewritten_together(self) -> None:
        from task_router import TaskManager

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = TaskManager(root / "tasks.jsonl", root / "runs", runner=lambda *args, **kwargs: 0)
            task = manager.submit(
                "https://example.test",
                "confirmed target intake",
                goal_id="G-004E-SCOPE",
                profile_name="standard-pentest",
                target_id="example-target",
                target_card_digest="a" * 64,
                idempotency_key="G-004E-SCOPE",
            )
            for _ in range(100):
                if manager.list_tasks()[0]["status"] != "running":
                    break
                time.sleep(0.02)
            task_dir = Path(task["output_path"])
            scope_path = task_dir / "scope.json"
            binding_path = task_dir / "evidence" / "task_binding.json"
            scope = json.loads(scope_path.read_text(encoding="utf-8"))
            scope["instruction_raw"] = "tampered instruction"
            scope["instruction_final"] = "tampered instruction"
            rewritten_scope = json.dumps(scope, ensure_ascii=False, indent=2, sort_keys=True)
            scope_path.write_text(rewritten_scope, encoding="utf-8")
            binding = json.loads(binding_path.read_text(encoding="utf-8"))
            binding["scope_sha256"] = __import__("hashlib").sha256(
                scope_path.read_bytes()
            ).hexdigest()
            binding_path.write_text(json.dumps(binding), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "^task_evidence_binding_invalid$"):
                TaskManager._validate_task_evidence_binding(task, task_dir)

    def test_task_evidence_binding_rejects_unrecognized_fields_before_ledger_projection(self) -> None:
        from task_router import TaskManager

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = TaskManager(root / "tasks.jsonl", root / "runs", runner=lambda *args, **kwargs: 0)
            task = manager.submit(
                "https://example.test",
                "/goal 测试 https://example.test",
                goal_id="G-004E1",
                profile_name="standard-pentest",
                target_id="example-target",
                target_card_digest="a" * 64,
                idempotency_key="G-004E1",
            )
            for _ in range(100):
                if manager.list_tasks()[0]["status"] == "finished":
                    break
                time.sleep(0.02)
            task_dir = Path(task["output_path"])
            binding_path = task_dir / "evidence" / "task_binding.json"
            binding = json.loads(binding_path.read_text(encoding="utf-8"))
            binding["unexpected_payload"] = "x" * 4096
            binding_path.write_text(json.dumps(binding), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "^task_evidence_binding_invalid$"):
                TaskManager._validate_task_evidence_binding(task, task_dir)

    def test_same_idempotency_key_cannot_change_the_bound_goal_request(self) -> None:
        from task_router import TaskManager

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = TaskManager(
                root / "tasks.jsonl",
                root / "runs",
                runner=lambda *args, **kwargs: 0,
            )
            manager.submit(
                "https://first.example.test",
                "测试第一个目标",
                goal_id="G-002",
                profile_name="standard-pentest",
                target_id="first-target",
                target_card_digest="a" * 64,
                idempotency_key="G-002",
            )
            with self.assertRaises(ValueError):
                manager.submit(
                    "https://second.example.test",
                    "测试第二个目标",
                    goal_id="G-002",
                    profile_name="standard-pentest",
                    target_id="second-target",
                    target_card_digest="b" * 64,
                    idempotency_key="G-002",
                )

            # submit() starts a background runner; wait for its terminal event
            # before TemporaryDirectory attempts Windows cleanup of the lock file.
            for _ in range(50):
                tasks = manager.list_tasks()
                if tasks and tasks[0]["status"] != "running":
                    break
                time.sleep(0.02)
            self.assertNotEqual("running", manager.list_tasks()[0]["status"])


class TaskRouterRecoveryTests(unittest.TestCase):
    @staticmethod
    def _wait_for_terminal(manager, task_id: str) -> dict:
        for _ in range(100):
            tasks = {task["id"]: task for task in manager.list_tasks()}
            task = tasks.get(task_id)
            if task is not None and task["status"] not in {"reserved", "running"}:
                return task
            time.sleep(0.02)
        raise AssertionError(f"task did not reach a terminal state: {task_id}")

    @staticmethod
    def _task_event(task_id: str, *, status: str, owner_pid: int = 0) -> dict:
        return {
            "event": "created",
            "id": task_id,
            "goal_id": "G-001",
            "profile_name": "standard-pentest",
            "target_id": "example-target",
            "target_card_digest": "a" * 64,
            "idempotency_key": "G-001",
            "target": "https://example.test",
            "instruction": "/goal 测试 https://example.test",
            "status": status,
            "created_ts": 1.0,
            "owner_pid": owner_pid,
        }

    def test_current_process_owner_is_alive_without_sending_a_windows_signal(self) -> None:
        from task_router import TaskManager

        with patch("task_router.os.kill") as kill:
            self.assertTrue(TaskManager._owner_is_alive(os.getpid()))

        kill.assert_not_called()

    def test_windows_owner_probe_never_uses_os_kill(self) -> None:
        from task_router import TaskManager

        with patch("task_router.os.name", "nt"), patch.object(
            TaskManager, "_windows_owner_is_alive", return_value=True, create=True
        ) as windows_probe, patch("task_router.os.kill") as kill:
            self.assertTrue(TaskManager._owner_is_alive(43210))

        windows_probe.assert_called_once_with(43210)
        kill.assert_not_called()

    def test_dead_owner_requires_explicit_recovery_before_a_new_task_can_start(self) -> None:
        from task_router import TaskManager

        calls = []

        def runner(command, cwd, env, log_path, timeout):
            calls.append(command)
            return 0

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tasks_path = root / "tasks.jsonl"
            tasks_path.write_text(
                json.dumps(self._task_event("T-001", status="running", owner_pid=999_999_999)) + "\n",
                encoding="utf-8",
            )
            manager = TaskManager(tasks_path, root / "runs", runner=runner)

            with self.assertRaisesRegex(RuntimeError, "^recovery_required:T-001$"):
                manager.submit(
                    "https://example.test",
                    "/goal 测试 https://example.test",
                    goal_id="G-001",
                    profile_name="standard-pentest",
                    target_id="example-target",
                    target_card_digest="a" * 64,
                    idempotency_key="G-001",
                )

            self.assertEqual("recovery_pending", manager.list_tasks()[0]["status"])
            self.assertEqual(
                "interrupted",
                manager.resolve_recovery("T-001", operator_note="confirmed old runner stopped")["status"],
            )
            started = manager.submit(
                "https://next.example.test",
                "/goal 测试 https://next.example.test",
                goal_id="G-002",
                profile_name="standard-pentest",
                target_id="next-target",
                target_card_digest="b" * 64,
                idempotency_key="G-002",
            )
            self.assertEqual("T-002", started["id"])
            self.assertEqual("finished", self._wait_for_terminal(manager, "T-002")["status"])
            self.assertEqual(1, len(calls))

    def test_matching_replay_finishes_a_reserved_task_directory_without_allocating_a_new_id(self) -> None:
        from task_router import TaskManager

        calls = []

        def runner(command, cwd, env, log_path, timeout):
            calls.append(command)
            return 0

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            task_dir = root / "runs" / "T-001"
            task_dir.mkdir(parents=True)
            reservation = self._task_event("T-001", status="reserved")
            reservation["event"] = "reserved"
            reservation["reserved_ts"] = 1.0
            reservation["output_path"] = str(task_dir)
            (root / "tasks.jsonl").write_text(json.dumps(reservation) + "\n", encoding="utf-8")
            manager = TaskManager(root / "tasks.jsonl", root / "runs", runner=runner)

            replay = manager.submit(
                "https://example.test",
                "/goal 测试 https://example.test",
                goal_id="G-001",
                profile_name="standard-pentest",
                target_id="example-target",
                target_card_digest="a" * 64,
                idempotency_key="G-001",
            )

            self.assertEqual("T-001", replay["id"])
            self.assertEqual("finished", self._wait_for_terminal(manager, "T-001")["status"])
            self.assertEqual(1, len(calls))
            scope = json.loads((task_dir / "scope.json").read_text(encoding="utf-8"))
            self.assertEqual("G-001", scope["goal_id"])

    def test_different_idempotency_key_is_busy_until_the_running_task_finishes(self) -> None:
        from task_router import BusyError, TaskManager

        entered = threading.Event()
        release = threading.Event()

        def runner(command, cwd, env, log_path, timeout):
            entered.set()
            release.wait(timeout=2)
            return 0

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = TaskManager(root / "tasks.jsonl", root / "runs", runner=runner)
            first = manager.submit(
                "https://first.example.test",
                "/goal 测试 https://first.example.test",
                goal_id="G-001",
                profile_name="standard-pentest",
                target_id="first-target",
                target_card_digest="a" * 64,
                idempotency_key="G-001",
            )
            try:
                self.assertTrue(entered.wait(timeout=2))
                with self.assertRaises(BusyError):
                    manager.submit(
                        "https://second.example.test",
                        "/goal 测试 https://second.example.test",
                        goal_id="G-002",
                        profile_name="standard-pentest",
                        target_id="second-target",
                        target_card_digest="b" * 64,
                        idempotency_key="G-002",
                    )
            finally:
                release.set()
            self.assertEqual("finished", self._wait_for_terminal(manager, first["id"])["status"])

    def test_final_state_write_failure_releases_local_slot_into_recovery(self) -> None:
        from task_router import TaskManager

        class FinalWriteFailureManager(TaskManager):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.fail_final_write = True

            def _append_unlocked(self, entry):
                if entry.get("event") == "finished" and self.fail_final_write:
                    self.fail_final_write = False
                    raise OSError("synthetic_final_write_failure")
                return super()._append_unlocked(entry)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = FinalWriteFailureManager(
                root / "tasks.jsonl",
                root / "runs",
                runner=lambda *args, **kwargs: 0,
            )
            first = manager.submit(
                "https://example.test",
                "/goal 测试 https://example.test",
                goal_id="G-001",
                profile_name="standard-pentest",
                target_id="example-target",
                target_card_digest="a" * 64,
                idempotency_key="G-001",
            )
            finalization_error = Path(first["output_path"]) / "finalization_error.json"
            for _ in range(100):
                if finalization_error.is_file():
                    break
                time.sleep(0.02)
            self.assertTrue(finalization_error.is_file())

            with self.assertRaisesRegex(RuntimeError, "^recovery_required:T-001$"):
                manager.submit(
                    "https://next.example.test",
                    "/goal 测试 https://next.example.test",
                    goal_id="G-002",
                    profile_name="standard-pentest",
                    target_id="next-target",
                    target_card_digest="b" * 64,
                    idempotency_key="G-002",
                )
            self.assertEqual("recovery_pending", manager.list_tasks()[0]["status"])


if __name__ == "__main__":
    unittest.main()
