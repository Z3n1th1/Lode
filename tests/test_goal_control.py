"""Regression contract for profile selection, goal lifecycle, and scoring."""
from __future__ import annotations

import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path


PENTEST_AGENT = Path(__file__).resolve().parents[1]
for directory in (PENTEST_AGENT / "core", PENTEST_AGENT / "notify"):
    sys.path.insert(0, str(directory))


class ProfileContractTests(unittest.TestCase):
    def test_runtime_profiles_match_the_canonical_profile_names(self) -> None:
        from operation_profile import get_profile, profile_names

        self.assertEqual(
            {
                "ctf-fast-score",
                "redteam",
                "offense-high-value",
                "standard-pentest",
                "daily-deliverable",
                "batch-asset-sweep",
                "cautious-waf-risk-control",
            },
            set(profile_names()),
        )
        standard = get_profile("standard-pentest")
        self.assertEqual("full_endpoint_assessment", standard["completion_scope"])
        self.assertTrue(standard["coverage_policy"]["endpoint_coverage_objective_enabled"])

    def test_profile_results_do_not_share_nested_mutable_registry_data(self) -> None:
        from operation_profile import get_profile

        first = get_profile("standard-pentest")
        first["coverage_policy"]["targets"]["endpoint_assessment_coverage"] = 0

        second = get_profile("standard-pentest")
        self.assertEqual(1.0, second["coverage_policy"]["targets"]["endpoint_assessment_coverage"])

    def test_new_target_without_explicit_profile_requires_a_choice(self) -> None:
        from operation_profile import resolve_request

        decision = resolve_request("/goal https://example.test/login")

        self.assertEqual("https://example.test/login", decision.target)
        self.assertTrue(decision.requires_profile_choice)
        self.assertFalse(decision.goal_exempt)

    def test_explicit_profile_starts_without_another_prompt(self) -> None:
        from operation_profile import resolve_request

        decision = resolve_request("/goal ctf https://example.test/challenge")

        self.assertEqual("ctf-fast-score", decision.profile_name)
        self.assertFalse(decision.requires_profile_choice)
        self.assertFalse(decision.goal_exempt)

    def test_conflicting_explicit_profiles_require_a_choice(self) -> None:
        from operation_profile import resolve_request

        decision = resolve_request("/goal ctf src https://example.test/challenge")

        self.assertIsNone(decision.profile_name)
        self.assertTrue(decision.requires_profile_choice)
        self.assertTrue(decision.profile_conflict)

    def test_only_traffic_analysis_is_explicitly_goal_exempt(self) -> None:
        from operation_profile import resolve_request

        decision = resolve_request("只分析 https://example.test 的 HAR 流量")

        self.assertTrue(decision.goal_exempt)
        self.assertFalse(decision.requires_profile_choice)

    def test_explicit_limited_analysis_is_also_goal_exempt(self) -> None:
        from operation_profile import resolve_request

        decision = resolve_request("只做限定分析 https://example.test")

        self.assertTrue(decision.goal_exempt)
        self.assertFalse(decision.requires_profile_choice)

    def test_http_url_alone_does_not_make_analysis_goal_exempt(self) -> None:
        from operation_profile import resolve_request

        decision = resolve_request("只分析 http://example.test")

        self.assertFalse(decision.goal_exempt)
        self.assertTrue(decision.requires_profile_choice)

    def test_target_extraction_preserves_textual_order(self) -> None:
        from operation_profile import extract_target

        self.assertEqual(
            "192.0.2.10",
            extract_target("/goal ctf 192.0.2.10 再测试 https://example.test/path"),
        )


class GoalLifecycleTests(unittest.TestCase):
    def test_new_goal_requires_a_canonical_target_identity(self) -> None:
        from goal_manager import GoalManager

        with tempfile.TemporaryDirectory() as tmp:
            manager = GoalManager(Path(tmp) / "goals.jsonl")
            with self.assertRaisesRegex(ValueError, "^target_identity_binding_required$"):
                manager.create_goal(
                    target="https://example.test",
                    profile_name="standard-pentest",
                    instruction="只读测试",
                )

    def test_goal_stops_only_on_coverage_timebox_or_confirmed_rce(self) -> None:
        from goal_manager import GoalManager

        with tempfile.TemporaryDirectory() as tmp:
            manager = GoalManager(Path(tmp) / "goals.jsonl")
            goal = manager.create_goal(
                target="https://example.test",
                profile_name="standard-pentest",
                instruction="测试登录和订单接口",
                endpoints_total=2,
                target_id="example-target",
                target_card_digest="a" * 64,
            )
            self.assertIsNone(manager.check_stop_conditions(goal.goal_id))

            manager.mark_endpoint_audited(goal.goal_id, "GET /login")
            self.assertIsNone(manager.check_stop_conditions(goal.goal_id))

            manager.mark_endpoint_audited(goal.goal_id, "GET /orders")
            self.assertEqual("all_endpoints_audited", manager.check_stop_conditions(goal.goal_id))

            rce_goal = manager.create_goal(
                target="https://rce.example.test",
                profile_name="standard-pentest",
                instruction="测试接口",
                target_id="rce-target",
                target_card_digest="b" * 64,
            )
            manager.record_finding(
                rce_goal.goal_id,
                {"severity": "critical", "type": "rce", "verified": True},
            )
            self.assertEqual("rce_confirmed", manager.check_stop_conditions(rce_goal.goal_id))

    def test_goal_state_reloads_and_respects_the_two_hour_timebox(self) -> None:
        from goal_manager import GoalManager

        now = [1_000.0]
        with tempfile.TemporaryDirectory() as tmp:
            goals_path = Path(tmp) / "goals.jsonl"
            manager = GoalManager(goals_path, now_fn=lambda: now[0])
            goal = manager.create_goal(
                target="https://example.test",
                profile_name="standard-pentest",
                instruction="测试个人资料接口",
                endpoints_total=2,
                target_id="example-target",
                target_card_digest="a" * 64,
            )
            manager.mark_endpoint_audited(goal.goal_id, "GET /profile")

            restored = GoalManager(goals_path, now_fn=lambda: now[0])
            self.assertEqual({"GET /profile"}, restored.get_goal(goal.goal_id).audited_endpoints)
            now[0] += 2 * 60 * 60
            self.assertEqual("timebox_2h", restored.check_stop_conditions(goal.goal_id))


class ScoringContractTests(unittest.TestCase):
    def test_frontend_crypto_material_is_capped_at_low(self) -> None:
        from scoring import score_finding

        result = score_finding(
            {
                "title": "前端返回 AES 加密密钥",
                "type": "frontend_crypto_key",
                "severity": "high",
                "evidence_level": "L1_single_branch",
            }
        )

        self.assertEqual("low", result["severity"])
        self.assertIn("前端", result["reason"])

    def test_high_requires_verifier_and_comparative_evidence(self) -> None:
        from scoring import score_finding

        result = score_finding(
            {
                "title": "疑似垂直越权",
                "type": "vertical_idor",
                "severity": "high",
                "evidence_level": "L2_differential_pair",
                "verified": False,
            }
        )

        self.assertEqual("medium", result["severity"])
        self.assertIn("Verifier", result["reason"])

    def test_unverified_critical_is_capped_at_medium(self) -> None:
        from scoring import score_finding

        result = score_finding(
            {"title": "疑似 RCE", "type": "rce", "severity": "critical", "verified": False}
        )

        self.assertEqual("medium", result["severity"])
        self.assertIn("Verifier", result["reason"])


class GoalControlTests(unittest.TestCase):
    def test_profile_selection_creates_a_durable_intake_preview_before_task_submission(self) -> None:
        from goal_control import GoalControl
        from goal_manager import GoalManager

        submitted = []

        class FakeTaskManager:
            def submit(self, target, instruction, **kwargs):
                submitted.append((target, instruction, kwargs))
                return {"id": "T-INTAKE-001", "target": target, "status": "running"}

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            control = GoalControl(
                goal_manager=GoalManager(root / "goals.jsonl"),
                task_manager=FakeTaskManager(),
                pending_path=root / "pending_profiles.jsonl",
                intake_path=root / "target_intakes.jsonl",
            )

            choice = control.accept_goal_request(
                "/goal https://example.test", user_id="u1", chat_id="c1", message_id="m1"
            )
            preview = control.consume_numeric_reply(
                "1", user_id="u1", chat_id="c1", message_id="m2"
            )

            self.assertEqual("profile_choice", choice["state"])
            self.assertEqual("intake_preview", preview["state"])
            self.assertEqual("TargetIntakePreview/v1", preview["preview"]["schema"])
            self.assertEqual("standard-pentest", preview["profile"])
            self.assertEqual([], submitted)
            self.assertFalse((root / "ai-pentest-evidence").exists())
            events = [
                json.loads(line)
                for line in (root / "target_intakes.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(["preview_created"], [event["event"] for event in events])

    def test_intake_confirmation_binds_target_card_to_goal_and_task(self) -> None:
        from goal_control import GoalControl
        from goal_manager import GoalManager

        submitted = []

        class FakeTaskManager:
            def submit(self, target, instruction, **kwargs):
                submitted.append((target, instruction, kwargs))
                return {"id": "T-INTAKE-002", "target": target, "status": "running"}

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            goals_path = root / "goals.jsonl"
            control = GoalControl(
                goal_manager=GoalManager(goals_path),
                task_manager=FakeTaskManager(),
                pending_path=root / "pending_profiles.jsonl",
                intake_path=root / "target_intakes.jsonl",
            )

            preview = control.accept_goal_request(
                "/goal ctf https://example.test", user_id="u1", chat_id="c1", message_id="m1"
            )
            confirmation = f"确认 {preview['preview']['intake_id']} {preview['preview']['options_digest']}"
            started = control.consume_intake_confirmation(
                confirmation, user_id="u1", chat_id="c1", message_id="m2"
            )

            self.assertEqual("intake_preview", preview["state"])
            self.assertEqual("started", started["state"])
            self.assertEqual("TargetCard/v1", started["target_card"]["schema"])
            self.assertEqual(1, len(submitted))
            self.assertEqual(started["target_card_digest"], submitted[0][2]["target_card_digest"])
            target_card_path = root / started["target_card_ref"]
            self.assertTrue(target_card_path.is_file())
            target_card_bytes = target_card_path.read_bytes()
            target_card = json.loads(target_card_bytes.decode("utf-8"))
            self.assertEqual(started["target_card"], target_card)
            from intake_state import canonical_digest

            self.assertEqual(started["target_card_digest"], canonical_digest(target_card))
            self.assertEqual(
                f"ai-pentest-evidence/projects/{started['target_id']}/target.yaml",
                started["target_card_ref"],
            )
            goals = [json.loads(line) for line in goals_path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(
                started["target_card_digest"],
                goals[0]["goal"]["target_card_digest"],
            )

    def test_intake_confirmation_replay_requires_the_same_create_once_target_card(self) -> None:
        from goal_control import GoalControl
        from goal_manager import GoalManager

        class FakeTaskManager:
            def submit(self, target, instruction, **kwargs):
                return {"id": "T-INTAKE-CARD-REPLAY", "status": "running"}

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            control = GoalControl(
                goal_manager=GoalManager(root / "goals.jsonl"),
                task_manager=FakeTaskManager(),
                pending_path=root / "pending_profiles.jsonl",
                intake_path=root / "target_intakes.jsonl",
                project_root=root,
            )
            preview = control.accept_goal_request(
                "/goal ctf https://example.test", user_id="u1", chat_id="c1", message_id="m1"
            )
            confirmation = f"confirm {preview['preview']['intake_id']} {preview['preview']['options_digest']}"
            first = control.consume_intake_confirmation(
                confirmation, user_id="u1", chat_id="c1", message_id="m2"
            )
            card_path = root / first["target_card_ref"]
            before = card_path.read_bytes()
            replay = control.consume_intake_confirmation(
                confirmation, user_id="u1", chat_id="c1", message_id="m3"
            )

            self.assertEqual("started", first["state"])
            self.assertEqual("started", replay["state"])
            self.assertEqual(first["target_card_digest"], replay["target_card_digest"])
            self.assertEqual(before, card_path.read_bytes())

            drifted = dict(first["target_card"])
            drifted["entrypoints"] = ["https://drift.example.test/"]
            card_path.write_text(json.dumps(drifted, ensure_ascii=False), encoding="utf-8")
            rejected = control.consume_intake_confirmation(
                confirmation, user_id="u1", chat_id="c1", message_id="m4"
            )

            self.assertEqual("state_error", rejected["state"])
            self.assertEqual("canonical_target_card_mismatch", rejected["reason"])

    def test_existing_yaml_target_card_with_the_same_digest_is_reused(self) -> None:
        from goal_control import GoalControl
        from goal_manager import GoalManager
        import yaml

        submitted = []

        class FakeTaskManager:
            def submit(self, target, instruction, **kwargs):
                submitted.append((target, instruction, kwargs))
                return {"id": "T-INTAKE-YAML", "status": "running"}

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            control = GoalControl(
                goal_manager=GoalManager(root / "goals.jsonl"),
                task_manager=FakeTaskManager(),
                pending_path=root / "pending_profiles.jsonl",
                intake_path=root / "target_intakes.jsonl",
                project_root=root,
            )
            preview = control.accept_goal_request(
                "/goal ctf https://example.test", user_id="u1", chat_id="c1", message_id="m1"
            )
            from intake_state import target_card_from_preview

            target_card = target_card_from_preview(control.intake_state.pending(user_id="u1", chat_id="c1"))
            target_card_path = root / "ai-pentest-evidence" / "projects" / target_card["target_id"] / "target.yaml"
            target_card_path.parent.mkdir(parents=True)
            target_card_path.write_text(
                yaml.safe_dump(target_card, allow_unicode=True, sort_keys=False), encoding="utf-8"
            )
            original_yaml = target_card_path.read_bytes()
            confirmation = f"confirm {preview['preview']['intake_id']} {preview['preview']['options_digest']}"

            started = control.consume_intake_confirmation(
                confirmation, user_id="u1", chat_id="c1", message_id="m2"
            )

            self.assertEqual("started", started["state"])
            self.assertEqual(target_card, started["target_card"])
            self.assertEqual(1, len(submitted))
            self.assertEqual(original_yaml, target_card_path.read_bytes())

    def test_second_intake_for_the_same_host_reuses_the_canonical_target_card(self) -> None:
        from goal_control import GoalControl
        from goal_manager import GoalManager

        now = [1_000.0]
        submitted = []

        class FakeTaskManager:
            def submit(self, target, instruction, **kwargs):
                submitted.append((target, instruction, kwargs))
                return {"id": f"T-INTAKE-{len(submitted)}", "status": "running"}

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            control = GoalControl(
                goal_manager=GoalManager(root / "goals.jsonl", now_fn=lambda: now[0]),
                task_manager=FakeTaskManager(),
                pending_path=root / "pending_profiles.jsonl",
                intake_path=root / "target_intakes.jsonl",
                now_fn=lambda: now[0],
                project_root=root,
            )
            first_preview = control.accept_goal_request(
                "/goal ctf https://example.test/first", user_id="u1", chat_id="c1", message_id="m1"
            )
            first = control.consume_intake_confirmation(
                f"confirm {first_preview['preview']['intake_id']} {first_preview['preview']['options_digest']}",
                user_id="u1",
                chat_id="c1",
                message_id="m2",
            )
            target_card_path = root / first["target_card_ref"]
            original_card = target_card_path.read_bytes()
            now[0] += 1
            second_preview = control.accept_goal_request(
                "/goal ctf https://example.test/second", user_id="u1", chat_id="c1", message_id="m3"
            )

            second = control.consume_intake_confirmation(
                f"confirm {second_preview['preview']['intake_id']} {second_preview['preview']['options_digest']}",
                user_id="u1",
                chat_id="c1",
                message_id="m4",
            )

            self.assertEqual("started", first["state"])
            self.assertEqual("started", second["state"])
            self.assertEqual(first["target_card_digest"], second["target_card_digest"])
            self.assertEqual(first["target_card"], second["target_card"])
            self.assertEqual(original_card, target_card_path.read_bytes())
            self.assertEqual(2, len(submitted))

    def test_divergent_existing_target_card_blocks_goal_and_task_creation(self) -> None:
        from goal_control import GoalControl
        from goal_manager import GoalManager

        submitted = []

        class FakeTaskManager:
            def submit(self, target, instruction, **kwargs):
                submitted.append((target, instruction, kwargs))
                return {"id": "T-INTAKE-CARD-CONFLICT", "status": "running"}

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            control = GoalControl(
                goal_manager=GoalManager(root / "goals.jsonl"),
                task_manager=FakeTaskManager(),
                pending_path=root / "pending_profiles.jsonl",
                intake_path=root / "target_intakes.jsonl",
                project_root=root,
            )
            preview = control.accept_goal_request(
                "/goal ctf https://example.test", user_id="u1", chat_id="c1", message_id="m1"
            )
            expected_id = "example-test-" + __import__("hashlib").sha256(
                b"example.test"
            ).hexdigest()[:12]
            card_path = root / "ai-pentest-evidence" / "projects" / expected_id / "target.yaml"
            card_path.parent.mkdir(parents=True)
            divergent = {
                "schema": "TargetCard/v1",
                "target_id": expected_id,
                "scenario": "unclassified",
                "scope": {"allowed_hosts": ["foreign.example.test"], "forbidden_hosts": []},
                "created_at": "2026-08-12T00:00:00Z",
                "updated_at": "2026-08-12T00:00:00Z",
                "entrypoints": ["https://foreign.example.test/"],
                "auth": {"required": False, "session_aliases": []},
                "notes": "synthetic conflicting card",
            }
            before = json.dumps(divergent, ensure_ascii=False, sort_keys=True).encode("utf-8")
            card_path.write_bytes(before)
            confirmation = f"确认 {preview['preview']['intake_id']} {preview['preview']['options_digest']}"

            result = control.consume_intake_confirmation(
                confirmation, user_id="u1", chat_id="c1", message_id="m2"
            )

            self.assertEqual("state_error", result["state"])
            self.assertEqual("canonical_target_card_mismatch", result["reason"])
            self.assertEqual(before, card_path.read_bytes())
            self.assertEqual([], submitted)
            self.assertFalse((root / "goals.jsonl").exists())

    def test_expired_intake_preview_does_not_submit_a_task(self) -> None:
        from goal_control import GoalControl
        from goal_manager import GoalManager

        now = [1_000.0]
        submitted = []

        class FakeTaskManager:
            def submit(self, target, instruction, **kwargs):
                submitted.append((target, instruction, kwargs))
                return {"id": "T-INTAKE-003", "target": target, "status": "running"}

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            control = GoalControl(
                goal_manager=GoalManager(root / "goals.jsonl", now_fn=lambda: now[0]),
                task_manager=FakeTaskManager(),
                pending_path=root / "pending_profiles.jsonl",
                intake_path=root / "target_intakes.jsonl",
                now_fn=lambda: now[0],
                intake_ttl_seconds=10,
            )
            preview = control.accept_goal_request(
                "/goal ctf https://example.test", user_id="u1", chat_id="c1", message_id="m1"
            )
            now[0] += 11

            expired = control.consume_intake_confirmation(
                f"confirm {preview['preview']['intake_id']} {preview['preview']['options_digest']}",
                user_id="u1",
                chat_id="c1",
                message_id="m2",
            )

            self.assertEqual("expired", expired["state"])
            self.assertEqual("intake_preview_expired", expired["reason"])
            self.assertEqual([], submitted)

    def test_confirmed_intake_rejects_a_new_confirmation_message_after_its_ttl(self) -> None:
        from goal_control import GoalControl
        from goal_manager import GoalManager

        now = [1_000.0]
        submitted = []

        class FakeTaskManager:
            def submit(self, target, instruction, **kwargs):
                submitted.append((target, instruction, kwargs))
                return {"id": "T-INTAKE-TTL", "status": "running"}

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            control = GoalControl(
                goal_manager=GoalManager(root / "goals.jsonl", now_fn=lambda: now[0]),
                task_manager=FakeTaskManager(),
                pending_path=root / "pending_profiles.jsonl",
                intake_path=root / "target_intakes.jsonl",
                now_fn=lambda: now[0],
                intake_ttl_seconds=10,
            )
            preview = control.accept_goal_request(
                "/goal ctf https://example.test", user_id="u1", chat_id="c1", message_id="m1"
            )
            confirmation = f"confirm {preview['preview']['intake_id']} {preview['preview']['options_digest']}"
            first = control.consume_intake_confirmation(
                confirmation, user_id="u1", chat_id="c1", message_id="m2"
            )
            now[0] += 11

            expired = control.consume_intake_confirmation(
                confirmation, user_id="u1", chat_id="c1", message_id="m3"
            )

            self.assertEqual("started", first["state"])
            self.assertEqual("expired", expired["state"])
            self.assertEqual("intake_confirmation_expired", expired["reason"])
            self.assertEqual(1, len(submitted))

    def test_intake_confirmation_rejects_a_different_options_digest(self) -> None:
        from goal_control import GoalControl
        from goal_manager import GoalManager

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            control = GoalControl(
                goal_manager=GoalManager(root / "goals.jsonl"),
                task_manager=None,
                pending_path=root / "pending_profiles.jsonl",
                intake_path=root / "target_intakes.jsonl",
            )
            preview = control.accept_goal_request(
                "/goal ctf https://example.test", user_id="u1", chat_id="c1", message_id="m1"
            )

            mismatch = control.consume_intake_confirmation(
                f"确认 {preview['preview']['intake_id']} {'0' * 64}",
                user_id="u1",
                chat_id="c1",
                message_id="m2",
            )

            self.assertEqual("state_error", mismatch["state"])
            self.assertEqual("intake_confirmation_binding_mismatch", mismatch["reason"])
            self.assertEqual(
                preview["preview"]["intake_id"],
                control.pending_intake_preview(user_id="u1", chat_id="c1")["intake_id"],
            )

    def test_confirmed_intake_replay_uses_the_original_instruction_and_one_task(self) -> None:
        from goal_control import GoalControl
        from goal_manager import GoalManager

        submissions = []

        class IdempotentTaskManager:
            def __init__(self) -> None:
                self.by_key = {}

            def submit(self, target, instruction, **kwargs):
                submissions.append((target, instruction, kwargs))
                return self.by_key.setdefault(kwargs["idempotency_key"], {"id": "T-INTAKE-REPLAY"})

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            control = GoalControl(
                goal_manager=GoalManager(root / "goals.jsonl"),
                task_manager=IdempotentTaskManager(),
                pending_path=root / "pending_profiles.jsonl",
                intake_path=root / "target_intakes.jsonl",
            )
            preview = control.accept_goal_request(
                "/goal ctf https://example.test 订单接口", user_id="u1", chat_id="c1", message_id="m1"
            )
            confirmation = f"确认 {preview['preview']['intake_id']} {preview['preview']['options_digest']}"
            first = control.consume_intake_confirmation(
                confirmation, user_id="u1", chat_id="c1", message_id="m2"
            )
            replay = control.consume_intake_confirmation(
                confirmation, user_id="u1", chat_id="c1", message_id="m2"
            )

            self.assertEqual("started", first["state"])
            self.assertEqual("started", replay["state"])
            self.assertEqual(2, len(submissions))
            self.assertEqual(submissions[0][1], submissions[1][1])
            self.assertIn("订单接口", submissions[0][1])
            self.assertEqual(first["target_card_digest"], submissions[0][2]["target_card_digest"])

    def test_second_confirmation_message_reuses_the_same_intake_receipt(self) -> None:
        from goal_control import GoalControl
        from goal_manager import GoalManager

        submissions = []

        class RecordingTaskManager:
            def submit(self, target, instruction, **kwargs):
                submissions.append(kwargs)
                return {"id": "T-INTAKE-SAME", "status": "running"}

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            control = GoalControl(
                goal_manager=GoalManager(root / "goals.jsonl"),
                task_manager=RecordingTaskManager(),
                pending_path=root / "pending_profiles.jsonl",
                intake_path=root / "target_intakes.jsonl",
            )
            preview = control.accept_goal_request(
                "/goal ctf https://example.test", user_id="u1", chat_id="c1", message_id="m1"
            )
            confirmation = f"confirm {preview['preview']['intake_id']} {preview['preview']['options_digest']}"
            first = control.consume_intake_confirmation(
                confirmation, user_id="u1", chat_id="c1", message_id="m2"
            )
            second = control.consume_intake_confirmation(
                confirmation, user_id="u1", chat_id="c1", message_id="m3"
            )

            self.assertEqual("started", first["state"])
            self.assertEqual("started", second["state"])
            self.assertEqual(first["goal_id"], second["goal_id"])
            self.assertEqual(2, len(submissions))
            self.assertEqual(submissions[0]["idempotency_key"], submissions[1]["idempotency_key"])

    def test_profile_prompt_then_numeric_choice_creates_an_intake_preview(self) -> None:
        from goal_control import GoalControl
        from goal_manager import GoalManager

        submitted = []

        class FakeTaskManager:
            def submit(self, target, instruction, **kwargs):
                submitted.append((target, instruction, kwargs))
                return {"id": "T-001", "target": target, "status": "running"}

        with tempfile.TemporaryDirectory() as tmp:
            manager = GoalManager(Path(tmp) / "goals.jsonl")
            control = GoalControl(
                goal_manager=manager,
                task_manager=FakeTaskManager(),
                pending_path=Path(tmp) / "pending_profiles.jsonl",
            )

            first = control.accept_goal_request(
                "/goal 测试 https://example.test", user_id="u1", chat_id="c1", message_id="m1"
            )
            self.assertEqual("profile_choice", first["state"])
            self.assertEqual([], submitted)

            selected = control.consume_numeric_reply(
                "1", user_id="u1", chat_id="c1", message_id="m2"
            )
            self.assertEqual("intake_preview", selected["state"])
            self.assertEqual("standard-pentest", selected["profile"])
            self.assertEqual([], submitted)

    def test_explicit_limited_analysis_does_not_create_goal_or_task(self) -> None:
        from goal_control import GoalControl
        from goal_manager import GoalManager

        class FakeTaskManager:
            def submit(self, *args, **kwargs):
                raise AssertionError("limited analysis must not submit a task")

        with tempfile.TemporaryDirectory() as tmp:
            control = GoalControl(
                goal_manager=GoalManager(Path(tmp) / "goals.jsonl"),
                task_manager=FakeTaskManager(),
                pending_path=Path(tmp) / "pending_profiles.jsonl",
            )
            result = control.accept_goal_request(
                "只分析 https://example.test 的 HAR 流量", user_id="u1", chat_id="c1", message_id="m1"
            )
            self.assertEqual("limited_analysis", result["state"])

    def test_pending_profile_choice_survives_a_restart(self) -> None:
        from goal_control import GoalControl
        from goal_manager import GoalManager

        submitted = []

        class FakeTaskManager:
            def submit(self, target, instruction, **kwargs):
                submitted.append((target, instruction, kwargs))
                return {"id": "T-002", "target": target, "status": "running"}

        with tempfile.TemporaryDirectory() as tmp:
            goals_path = Path(tmp) / "goals.jsonl"
            pending_path = Path(tmp) / "pending_profiles.jsonl"
            first = GoalControl(
                goal_manager=GoalManager(goals_path),
                task_manager=FakeTaskManager(),
                pending_path=pending_path,
            )
            choice = first.accept_goal_request(
                "/goal 测试 https://example.test", user_id="u1", chat_id="c1", message_id="m1"
            )
            self.assertEqual("profile_choice", choice["state"])

            restored = GoalControl(
                goal_manager=GoalManager(goals_path),
                task_manager=FakeTaskManager(),
                pending_path=pending_path,
            )
            preview = restored.consume_numeric_reply(
                "1", user_id="u1", chat_id="c1", message_id="m2"
            )
            confirmation = f"确认 {preview['preview']['intake_id']} {preview['preview']['options_digest']}"
            started = restored.consume_intake_confirmation(
                confirmation, user_id="u1", chat_id="c1", message_id="m3"
            )

            self.assertEqual("intake_preview", preview["state"])
            self.assertEqual("standard-pentest", preview["profile"])
            self.assertEqual("started", started["state"])
            self.assertEqual(1, len(submitted))

    def test_stale_second_consumer_cannot_submit_the_same_choice_twice(self) -> None:
        from goal_control import GoalControl
        from goal_manager import GoalManager

        submitted = []

        class FakeTaskManager:
            def submit(self, target, instruction, **kwargs):
                submitted.append((target, instruction, kwargs))
                return {"id": f"T-{len(submitted):03d}", "status": "running"}

        with tempfile.TemporaryDirectory() as tmp:
            goals_path = Path(tmp) / "goals.jsonl"
            pending_path = Path(tmp) / "pending_profiles.jsonl"
            first = GoalControl(
                goal_manager=GoalManager(goals_path),
                task_manager=FakeTaskManager(),
                pending_path=pending_path,
            )
            first.accept_goal_request(
                "/goal 测试 https://example.test", user_id="u1", chat_id="c1", message_id="m1"
            )
            second = GoalControl(
                goal_manager=GoalManager(goals_path),
                task_manager=FakeTaskManager(),
                pending_path=pending_path,
            )

            self.assertEqual(
                "intake_preview",
                first.consume_numeric_reply("1", user_id="u1", chat_id="c1", message_id="m2")["state"],
            )
            self.assertEqual(
                "ignored",
                second.consume_numeric_reply("1", user_id="u1", chat_id="c1", message_id="m3")["state"],
            )
            self.assertEqual([], submitted)

    def test_task_start_failure_keeps_the_same_goal_available_for_retry(self) -> None:
        from goal_control import GoalControl
        from goal_manager import GoalManager

        class FailingTaskManager:
            def submit(self, *args, **kwargs):
                raise RuntimeError("task_runner_unavailable")

        with tempfile.TemporaryDirectory() as tmp:
            goals_path = Path(tmp) / "goals.jsonl"
            control = GoalControl(
                goal_manager=GoalManager(goals_path),
                task_manager=FailingTaskManager(),
                pending_path=Path(tmp) / "pending_profiles.jsonl",
            )
            control.accept_goal_request(
                "/goal 测试 https://example.test", user_id="u1", chat_id="c1", message_id="m1"
            )
            preview = control.consume_numeric_reply("1", user_id="u1", chat_id="c1", message_id="m2")
            confirmation = f"确认 {preview['preview']['intake_id']} {preview['preview']['options_digest']}"
            first = control.consume_intake_confirmation(confirmation, user_id="u1", chat_id="c1", message_id="m3")
            second = control.consume_intake_confirmation(confirmation, user_id="u1", chat_id="c1", message_id="m4")

            self.assertEqual("task_error", first["state"])
            self.assertEqual("task_error", second["state"])
            self.assertEqual(first["goal_id"], second["goal_id"])
            events = [json.loads(line) for line in goals_path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(1, sum(event["event"] == "created" for event in events))

    def test_duplicate_explicit_profile_message_is_idempotent(self) -> None:
        from goal_control import GoalControl
        from goal_manager import GoalManager

        submitted = []

        class FakeTaskManager:
            def submit(self, target, instruction, **kwargs):
                submitted.append((target, instruction, kwargs))
                return {"id": "T-003", "status": "running"}

        with tempfile.TemporaryDirectory() as tmp:
            control = GoalControl(
                goal_manager=GoalManager(Path(tmp) / "goals.jsonl"),
                task_manager=FakeTaskManager(),
                pending_path=Path(tmp) / "pending_profiles.jsonl",
            )
            first = control.accept_goal_request(
                "/goal ctf https://example.test", user_id="u1", chat_id="c1", message_id="m1"
            )
            duplicate = control.accept_goal_request(
                "/goal ctf https://example.test", user_id="u1", chat_id="c1", message_id="m1"
            )

            self.assertEqual("intake_preview", first["state"])
            self.assertEqual("intake_preview", duplicate["state"])
            self.assertEqual(first["goal_id"], duplicate["goal_id"])
            self.assertEqual([], submitted)

    def test_second_target_does_not_retarget_an_existing_profile_choice(self) -> None:
        from goal_control import GoalControl
        from goal_manager import GoalManager

        submitted = []

        class FakeTaskManager:
            def submit(self, target, instruction, **kwargs):
                submitted.append((target, instruction, kwargs))
                return {"id": "T-004", "status": "running"}

        with tempfile.TemporaryDirectory() as tmp:
            control = GoalControl(
                goal_manager=GoalManager(Path(tmp) / "goals.jsonl"),
                task_manager=FakeTaskManager(),
                pending_path=Path(tmp) / "pending_profiles.jsonl",
            )
            first = control.accept_goal_request(
                "/goal https://first.example.test", user_id="u1", chat_id="c1", message_id="m1"
            )
            second = control.accept_goal_request(
                "/goal https://second.example.test", user_id="u1", chat_id="c1", message_id="m2"
            )
            preview = control.consume_numeric_reply("1", user_id="u1", chat_id="c1", message_id="m3")

            self.assertEqual("https://first.example.test", first["target"])
            self.assertEqual("https://first.example.test", second["target"])
            self.assertEqual("pending_profile_choice_exists", second["reason"])
            self.assertEqual("https://first.example.test", preview["target"])
            self.assertEqual([], submitted)

    def test_submit_then_pending_log_failure_reuses_the_task_idempotency_key(self) -> None:
        from goal_control import DEFAULT_CLAIM_LEASE_SECONDS, GoalControl
        from goal_manager import GoalManager

        now = [1_000.0]
        submissions = []

        class IdempotentTaskManager:
            def __init__(self):
                self.tasks = {}

            def submit(self, target, instruction, **kwargs):
                key = kwargs["idempotency_key"]
                if key not in self.tasks:
                    submissions.append((target, instruction, kwargs))
                    self.tasks[key] = {"id": "T-005", "status": "running"}
                return self.tasks[key]

        class ConsumeWriteFailureControl(GoalControl):
            def __init__(self, **kwargs):
                super().__init__(**kwargs)
                self.fail_consumed_write = True

            def _append_pending_event(self, event):
                if event.get("event") == "consumed" and self.fail_consumed_write:
                    self.fail_consumed_write = False
                    raise OSError("synthetic_pending_write_failure")
                return super()._append_pending_event(event)

        with tempfile.TemporaryDirectory() as tmp:
            task_manager = IdempotentTaskManager()
            control = ConsumeWriteFailureControl(
                goal_manager=GoalManager(Path(tmp) / "goals.jsonl", now_fn=lambda: now[0]),
                task_manager=task_manager,
                pending_path=Path(tmp) / "pending_profiles.jsonl",
                now_fn=lambda: now[0],
            )
            control.accept_goal_request(
                "/goal https://example.test", user_id="u1", chat_id="c1", message_id="m1"
            )
            preview = control.consume_numeric_reply("1", user_id="u1", chat_id="c1", message_id="m2")
            confirmation = f"确认 {preview['preview']['intake_id']} {preview['preview']['options_digest']}"
            uncertain = control.consume_intake_confirmation(confirmation, user_id="u1", chat_id="c1", message_id="m3")
            now[0] += DEFAULT_CLAIM_LEASE_SECONDS + 1
            retried = control.consume_intake_confirmation(confirmation, user_id="u1", chat_id="c1", message_id="m4")

            self.assertEqual("started", uncertain["state"])
            self.assertEqual("started", retried["state"])
            self.assertEqual(1, len(submissions))

    def test_concurrent_intake_confirmations_reuse_one_goal_idempotency_key(self) -> None:
        from goal_control import GoalControl
        from goal_manager import GoalManager

        first_entered = threading.Event()
        first_release = threading.Event()
        results = {}

        class ControlledTaskManager:
            def __init__(self) -> None:
                self.created = {}
                self.calls = []

            def submit(self, target, instruction, **kwargs):
                key = kwargs["idempotency_key"]
                self.calls.append(key)
                if key not in self.created:
                    self.created[key] = {"id": "T-006", "status": "running"}
                    first_entered.set()
                    first_release.wait(timeout=5)
                return self.created[key]

        with tempfile.TemporaryDirectory() as tmp:
            task_manager = ControlledTaskManager()
            control = GoalControl(
                goal_manager=GoalManager(Path(tmp) / "goals.jsonl"),
                task_manager=task_manager,
                pending_path=Path(tmp) / "pending_profiles.jsonl",
            )
            preview = control.accept_goal_request(
                "/goal ctf https://example.test", user_id="u1", chat_id="c1", message_id="m1"
            )
            confirmation = f"confirm {preview['preview']['intake_id']} {preview['preview']['options_digest']}"
            first = threading.Thread(
                target=lambda: results.setdefault(
                    "first",
                    control.consume_intake_confirmation(
                        confirmation, user_id="u1", chat_id="c1", message_id="m2"
                    ),
                )
            )
            second = threading.Thread(
                target=lambda: results.setdefault(
                    "second",
                    control.consume_intake_confirmation(
                        confirmation, user_id="u1", chat_id="c1", message_id="m3"
                    ),
                )
            )
            first.start()
            self.assertTrue(first_entered.wait(timeout=5))
            second.start()
            first_release.set()
            first.join(timeout=5)
            second.join(timeout=5)

            self.assertEqual("started", results["first"]["state"])
            self.assertEqual("started", results["second"]["state"])
            self.assertEqual(results["first"]["goal_id"], results["second"]["goal_id"])
            self.assertEqual(1, len(task_manager.created))
            self.assertTrue(all(key == results["first"]["goal_id"] for key in task_manager.calls))

    def test_duplicate_numeric_reply_returns_the_durable_intake_preview(self) -> None:
        from goal_control import GoalControl
        from goal_manager import GoalManager

        submitted = []

        class FakeTaskManager:
            def submit(self, target, instruction, **kwargs):
                submitted.append(kwargs)
                return {"id": "T-007", "status": "running"}

        with tempfile.TemporaryDirectory() as tmp:
            control = GoalControl(
                goal_manager=GoalManager(Path(tmp) / "goals.jsonl"),
                task_manager=FakeTaskManager(),
                pending_path=Path(tmp) / "pending_profiles.jsonl",
            )
            control.accept_goal_request(
                "/goal https://example.test", user_id="u1", chat_id="c1", message_id="m1"
            )
            first = control.consume_numeric_reply("1", user_id="u1", chat_id="c1", message_id="m2")
            duplicate = control.consume_numeric_reply("1", user_id="u1", chat_id="c1", message_id="m2")

            self.assertEqual("intake_preview", first["state"])
            self.assertEqual("intake_preview", duplicate["state"])
            self.assertEqual(first["goal_id"], duplicate["goal_id"])
            self.assertEqual(first["preview"]["intake_id"], duplicate["preview"]["intake_id"])
            self.assertEqual([], submitted)

    def test_state_storage_error_returns_a_retriable_result(self) -> None:
        from goal_control import GoalControl
        from goal_manager import GoalManager

        class BrokenPendingStore(GoalControl):
            def _append_pending_event(self, event):
                raise OSError("synthetic_disk_failure")

        with tempfile.TemporaryDirectory() as tmp:
            control = BrokenPendingStore(
                goal_manager=GoalManager(Path(tmp) / "goals.jsonl"),
                task_manager=None,
                pending_path=Path(tmp) / "pending_profiles.jsonl",
            )
            result = control.accept_goal_request(
                "/goal https://example.test", user_id="u1", chat_id="c1", message_id="m1"
            )

            self.assertEqual("state_error", result["state"])
            self.assertEqual("state_store_unavailable", result["reason"])


if __name__ == "__main__":
    unittest.main()
