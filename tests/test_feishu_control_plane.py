"""Regression contracts for the Feishu goal-control adapter."""
from __future__ import annotations

import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch


PENTEST_AGENT = Path(__file__).resolve().parents[1]
for directory in (PENTEST_AGENT / "core", PENTEST_AGENT / "notify"):
    sys.path.insert(0, str(directory))


class FeishuReactionClientTests(unittest.TestCase):
    def test_ack_reaction_uses_the_official_message_reactions_endpoint(self) -> None:
        from feishu_client import add_reaction

        with patch("feishu_client._request", return_value={"data": {"reaction_id": "r-1"}}) as request:
            reaction_id = add_reaction("tenant-token", "om_message")

        self.assertEqual("r-1", reaction_id)
        request.assert_called_once_with(
            "POST",
            "/open-apis/im/v1/messages/om_message/reactions",
            token="tenant-token",
            body={"reaction_type": {"emoji_type": "THUMBSUP"}},
        )

    def test_reply_uses_the_official_message_reply_endpoint(self) -> None:
        from feishu_client import reply_text

        with patch("feishu_client._request", return_value={"data": {"message_id": "om_reply"}}) as request:
            message_id = reply_text("tenant-token", "om_request", "短消息")

        self.assertEqual("om_reply", message_id)
        request.assert_called_once_with(
            "POST",
            "/open-apis/im/v1/messages/om_request/reply",
            token="tenant-token",
            body={"msg_type": "text", "content": '{"text": "短消息"}'},
        )

    def test_sender_reuses_one_tenant_token_for_acknowledgement_and_reply(self) -> None:
        from feishu_reply_consumer import FeishuMessageSender

        with patch("feishu_client.get_tenant_access_token", return_value="tenant-token") as get_token, patch(
            "feishu_client.add_reaction"
        ) as add_reaction, patch("feishu_client.send_text") as send_text, patch(
            "feishu_client.reply_text"
        ) as reply_text:
            sender = FeishuMessageSender("app-id", "app-secret")
            sender.acknowledge("om_message")
            sender.send_text("oc_chat", "短消息")
            sender.reply_text("om_message", "回复消息")

        get_token.assert_called_once_with("app-id", "app-secret")
        add_reaction.assert_called_once_with("tenant-token", "om_message")
        send_text.assert_called_once_with("tenant-token", "oc_chat", "短消息")
        reply_text.assert_called_once_with("tenant-token", "om_message", "回复消息")

    def test_sender_routes_broadcasts_with_its_cached_tenant_token(self) -> None:
        from feishu_reply_consumer import FeishuMessageSender

        with patch("feishu_client.get_tenant_access_token", return_value="tenant-token") as get_token, patch(
            "notifier.resolve_chat_id", return_value="oc_ops"
        ) as resolve_chat_id, patch("feishu_client.send_text") as send_text:
            sender = FeishuMessageSender("app-id", "app-secret")
            sender.send_by_category("ops_selfcheck", "进度短报")

        get_token.assert_called_once_with("app-id", "app-secret")
        resolve_chat_id.assert_called_once_with("ops_selfcheck")
        send_text.assert_called_once_with("tenant-token", "oc_ops", "进度短报")

    def test_sender_redacts_sensitive_text_before_feishu_transport(self) -> None:
        from feishu_reply_consumer import FeishuMessageSender

        with patch("feishu_client.get_tenant_access_token", return_value="tenant-token"), patch(
            "feishu_client.send_text"
        ) as send_text:
            sender = FeishuMessageSender("app-id", "app-secret")
            sender.send_text(
                "oc_chat",
                "状态\nAuthorization: Bearer transport-sentinel\nCookie: sid=cookie-sentinel",
            )

        outbound = send_text.call_args.args[2]
        self.assertNotIn("transport-sentinel", outbound)
        self.assertNotIn("cookie-sentinel", outbound)
        self.assertIn("已脱敏", outbound)

    def test_low_level_feishu_transport_blocks_report_body(self) -> None:
        import json
        from feishu_client import send_card, send_text

        with patch("feishu_client._request", return_value={"data": {"message_id": "m-safe"}}) as request:
            send_text(
                "tenant-token",
                "oc_chat",
                "# Penetration Test Report\nreport-body-sentinel\nAuthorization: Bearer secret",
            )
            text_body = request.call_args.kwargs["body"]
            text = json.loads(text_body["content"])["text"]
            self.assertNotIn("report-body-sentinel", text)
            self.assertIn("本地保密内容已拦截", text)

            send_card(
                "tenant-token",
                "oc_chat",
                {"header": {"title": "状态"}, "report": "card-report-sentinel"},
            )
            card_body = request.call_args.kwargs["body"]
            card = json.loads(card_body["content"])
            self.assertNotIn("card-report-sentinel", json.dumps(card, ensure_ascii=False))
            self.assertIn("本地保密内容已拦截", card["report"])


class FeishuCommandParsingTests(unittest.TestCase):
    def test_approval_target_and_message_size_are_bounded(self) -> None:
        from feishu_reply_consumer import CommandDispatcher

        with tempfile.TemporaryDirectory() as tmp:
            dispatcher = CommandDispatcher(
                ["ou_trusted"], Path(tmp) / "commands.jsonl", seen_file=Path(tmp) / "seen.json"
            )
            invalid = dispatcher.handle_message(
                user_id="ou_trusted", message_id="m-invalid-target",
                text="approve https://example.test/delete",
            )
            self.assertFalse(invalid["handled"])
            self.assertEqual("invalid_command_target", invalid["reason"])
            oversized = dispatcher.handle_message(
                user_id="ou_trusted", message_id="m-large",
                text="status " + ("x" * 5000),
            )
            self.assertFalse(oversized["handled"])
            self.assertEqual("message_too_large", oversized["reason"])

    def test_leading_group_mention_is_removed_before_command_parsing(self) -> None:
        from feishu_reply_consumer import CommandDispatcher

        with tempfile.TemporaryDirectory() as tmp:
            dispatcher = CommandDispatcher(
                ["ou_trusted"], Path(tmp) / "commands.jsonl", seen_file=Path(tmp) / "seen.json"
            )
            result = dispatcher.handle_message(
                user_id="ou_trusted",
                chat_id="oc_test",
                message_id="m-mentioned",
                text='<at user_id="ou_bot">小夏</at> status',
            )

        self.assertEqual({"handled": True, "action": "status", "target": "", "reply": "已受理: status"}, result)


class FeishuRuntimeFactoryTests(unittest.TestCase):
    def test_missing_strix_binary_returns_a_truthful_unavailable_task_adapter(self) -> None:
        from feishu_reply_consumer import build_task_manager

        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            "os.environ", {"STRIX_BIN": str(Path(tmp) / "missing-strix")}, clear=False
        ):
            manager = build_task_manager(Path(tmp) / "state")
            with self.assertRaisesRegex(RuntimeError, "^strix_runner_unavailable$"):
                manager.submit(
                    "https://example.test",
                    "/goal 测试 https://example.test",
                    goal_id="G-001",
                    profile_name="standard-pentest",
                    idempotency_key="G-001",
                )
            self.assertEqual([], manager.list_tasks())

    def test_broadcast_event_handler_maps_task_lifecycle_to_start_and_terminal_updates(self) -> None:
        from feishu_reply_consumer import build_broadcast_event_handler

        calls = []

        class RecordingBroadcaster:
            def broadcast_start(self, target, strategy, estimated_time):
                calls.append(("start", target, strategy, estimated_time))

            def broadcast_task_progress(self, target, **kwargs):
                calls.append(("progress", target, kwargs))

            def broadcast_task_terminal(self, target, **kwargs):
                calls.append(("terminal", target, kwargs))

        handler = build_broadcast_event_handler(RecordingBroadcaster())
        task = {
            "id": "T-001",
            "target": "https://example.test",
            "profile_name": "standard-pentest",
            "created_ts": 100.0,
        }
        handler("started", task)
        handler("progress", {**task, "elapsed_seconds": 65.0})
        handler("finished", {**task, "finished_ts": 160.0, "report_path": "private/report.md"})

        self.assertEqual(("start", "https://example.test", "标准授权渗透", "2小时"), calls[0])
        self.assertEqual("progress", calls[1][0])
        self.assertEqual("1分钟", calls[1][2]["elapsed"])
        self.assertEqual("terminal", calls[2][0])
        self.assertEqual("finished", calls[2][2]["status"])
        self.assertEqual("1分钟", calls[2][2]["elapsed"])
        self.assertTrue(calls[2][2]["report_ready"])

    def test_broadcast_event_handler_routes_only_confirmed_medium_or_higher_findings(self) -> None:
        from feishu_reply_consumer import build_broadcast_event_handler

        calls = []

        class RecordingBroadcaster:
            def broadcast_finding(self, severity, finding_id, title, detail, target, evidence_ref=""):
                calls.append((severity, finding_id, title, detail, target, evidence_ref))

        handler = build_broadcast_event_handler(RecordingBroadcaster())
        task = {"id": "T-001", "target": "https://example.test"}
        handler(
            "verified_finding",
            {
                **task,
                "finding": {
                    "finding_id": "F-001",
                    "title": "已验证垂直越权",
                    "detail": "token=private-evidence-value",
                    "type": "vertical_idor",
                    "severity": "high",
                    "evidence_level": "L3_reproducible_impact",
                    "verifier_status": "confirmed",
                    "evidence_ref": "E-001",
                },
            },
        )
        handler(
            "verified_finding",
            {
                **task,
                "finding": {
                    "finding_id": "F-002",
                    "title": "前端返回 AES 加密密钥",
                    "type": "frontend_crypto_key",
                    "severity": "high",
                    "evidence_level": "L3_reproducible_impact",
                    "verifier_status": "confirmed",
                },
            },
        )
        handler(
            "verified_finding",
            {
                **task,
                "finding": {
                    "finding_id": "F-003",
                    "title": "未验证候选",
                    "severity": "medium",
                },
            },
        )

        self.assertEqual(
            [("H", "F-001", "垂直越权", "已通过独立复核，详细证据保留在本地索引", "https://example.test", "E-001")],
            calls,
        )

    def test_task_manager_lifecycle_reaches_the_broadcaster_adapter(self) -> None:
        from feishu_reply_consumer import build_broadcast_event_handler
        from task_router import TaskManager

        calls = []

        class RecordingBroadcaster:
            def broadcast_start(self, target, strategy, estimated_time):
                calls.append(("start", target, strategy, estimated_time))

            def broadcast_task_terminal(self, target, **kwargs):
                calls.append(("terminal", target, kwargs))

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = TaskManager(
                root / "tasks.jsonl",
                root / "runs",
                runner=lambda *args, **kwargs: 0,
                event_fn=build_broadcast_event_handler(RecordingBroadcaster()),
            )
            manager.submit(
                "https://example.test",
                "/goal 测试 https://example.test",
                goal_id="G-030",
                profile_name="standard-pentest",
                target_id="example-target",
                target_card_digest="a" * 64,
                idempotency_key="G-030",
            )
            for _ in range(100):
                if len(calls) == 2:
                    break
                time.sleep(0.02)

        self.assertEqual("start", calls[0][0])
        self.assertEqual("terminal", calls[1][0])
        self.assertEqual("finished", calls[1][2]["status"])


class FeishuGoalControlTests(unittest.TestCase):
    class FakeGoalControl:
        def __init__(self) -> None:
            self.accepted = []
            self.numeric = []
            self.numeric_result = {
                "state": "profile_choice",
                "target": "https://example.test",
                "prompt": "请选择本次测试策略，回复编号：\n1. standard-pentest",
            }

        def accept_goal_request(self, instruction, *, user_id, chat_id, message_id):
            self.accepted.append((instruction, user_id, chat_id, message_id))
            return {
                "state": "profile_choice",
                "target": "https://example.test",
                "prompt": "请选择本次测试策略，回复编号：\n1. standard-pentest",
            }

        def consume_numeric_reply(self, reply, *, user_id, chat_id, message_id):
            self.numeric.append((reply, user_id, chat_id, message_id))
            return dict(self.numeric_result)

        def consume_intake_confirmation(self, confirmation, *, user_id, chat_id, message_id):
            self.confirmation = (confirmation, user_id, chat_id, message_id)
            return {
                "state": "started",
                "target": "https://example.test",
                "profile": "standard-pentest",
                "goal_id": "G-INTAKE",
                "task": {"id": "T-INTAKE", "status": "blocked"},
            }

    class FakeTaskManager:
        def list_tasks(self, limit=10):
            return [
                {
                    "id": "T-010",
                    "chat_id": "oc_test",
                    "target": "https://example.test",
                    "status": "finished",
                    "goal_id": "G-010",
                    "profile_name": "standard-pentest",
                    "report_path": "evidence/reports/T-010.md",
                }
            ][:limit]

    def _dispatcher(self, root: Path, goal_control, acks):
        from feishu_reply_consumer import CommandDispatcher

        return CommandDispatcher(
            ["ou_trusted"],
            root / "commands.jsonl",
            seen_file=root / "seen.json",
            goal_control=goal_control,
            task_manager=self.FakeTaskManager(),
            ack_fn=lambda message_id: acks.append(message_id),
        )

    def test_new_target_prompts_for_profile_and_acknowledges_once_across_restart(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            goal_control = self.FakeGoalControl()
            acks = []
            dispatcher = self._dispatcher(root, goal_control, acks)

            first = dispatcher.handle_message(
                user_id="ou_trusted",
                chat_id="oc_test",
                message_id="m-goal",
                text="请测试 https://example.test 的订单接口",
            )
            duplicate = dispatcher.handle_message(
                user_id="ou_trusted",
                chat_id="oc_test",
                message_id="m-goal",
                text="请测试 https://example.test 的订单接口",
            )
            restored = self._dispatcher(root, goal_control, acks)
            replay = restored.handle_message(
                user_id="ou_trusted",
                chat_id="oc_test",
                message_id="m-goal",
                text="请测试 https://example.test 的订单接口",
            )

        self.assertTrue(first["handled"])
        self.assertEqual("goal", first["channel"])
        self.assertIn("请选择本次测试策略", first["reply"])
        self.assertEqual({"handled": False, "reason": "duplicate"}, duplicate)
        self.assertEqual({"handled": False, "reason": "duplicate"}, replay)
        self.assertEqual(1, len(goal_control.accepted))
        self.assertEqual(["m-goal"], acks)

    def test_numeric_profile_choice_wins_over_report_detail_expansion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            goal_control = self.FakeGoalControl()
            goal_control.numeric_result = {
                "state": "started",
                "target": "https://example.test",
                "profile": "standard-pentest",
                "goal_id": "G-010",
                "task": {"id": "T-010", "status": "running"},
            }
            acks = []
            result = self._dispatcher(root, goal_control, acks).handle_message(
                user_id="ou_trusted",
                chat_id="oc_test",
                message_id="m-profile",
                text="1",
            )

        self.assertEqual("goal", result["channel"])
        self.assertIn("已开始", result["reply"])
        self.assertEqual([("1", "ou_trusted", "oc_test", "m-profile")], goal_control.numeric)
        self.assertEqual(["m-profile"], acks)

    def test_explicit_intake_confirmation_is_dispatched_before_task_detail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            goal_control = self.FakeGoalControl()
            acks = []
            result = self._dispatcher(root, goal_control, acks).handle_message(
                user_id="ou_trusted",
                chat_id="oc_test",
                message_id="m-intake",
                text=f"确认 I-001 {'a' * 64}",
            )

        self.assertEqual("goal", result["channel"])
        self.assertIn("已开始", result["reply"])
        self.assertEqual(
            (f"确认 I-001 {'a' * 64}", "ou_trusted", "oc_test", "m-intake"),
            goal_control.confirmation,
        )
        self.assertEqual(["m-intake"], acks)

    def test_one_expands_sanitized_task_detail_when_no_profile_choice_is_pending(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            goal_control = self.FakeGoalControl()
            goal_control.numeric_result = {"state": "ignored", "reason": "no_pending_profile_choice"}
            acks = []
            result = self._dispatcher(root, goal_control, acks).handle_message(
                user_id="ou_trusted",
                chat_id="oc_test",
                message_id="m-detail",
                text="1",
            )

        self.assertEqual("detail", result["channel"])
        self.assertIn("T-010", result["reply"])
        self.assertIn("已完成", result["reply"])
        self.assertNotIn("evidence/reports/T-010.md", result["reply"])
        self.assertEqual(["m-detail"], acks)

    def test_real_goal_control_requires_intake_confirmation_before_starting_one_bound_task(self) -> None:
        from feishu_reply_consumer import CommandDispatcher
        from goal_control import GoalControl
        from goal_manager import GoalManager

        submissions = []

        class RecordingTaskManager:
            def submit(self, target, instruction, **kwargs):
                submissions.append((target, instruction, kwargs))
                return {"id": "T-020", "status": "running", "chat_id": kwargs["chat_id"]}

            def list_tasks(self, limit=10):
                return []

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            control = GoalControl(
                goal_manager=GoalManager(root / "goals.jsonl"),
                task_manager=RecordingTaskManager(),
                pending_path=root / "pending_profiles.jsonl",
            )
            dispatcher = CommandDispatcher(
                ["ou_trusted"],
                root / "commands.jsonl",
                seen_file=root / "seen.json",
                goal_control=control,
            )
            pending = dispatcher.handle_message(
                user_id="ou_trusted",
                chat_id="oc_test",
                message_id="m-real-goal",
                text="/goal 测试 https://example.test",
            )
            preview = dispatcher.handle_message(
                user_id="ou_trusted",
                chat_id="oc_test",
                message_id="m-real-choice",
                text="1",
            )
            intake = control.pending_intake_preview(user_id="ou_trusted", chat_id="oc_test")
            started = dispatcher.handle_message(
                user_id="ou_trusted",
                chat_id="oc_test",
                message_id="m-real-confirm",
                text=f"确认 {intake['intake_id']} {intake['options_digest']}",
            )

        self.assertIn("请选择本次测试策略", pending["reply"])
        self.assertIn("目标预检", preview["reply"])
        self.assertIn("已开始", started["reply"])
        self.assertEqual(1, len(submissions))
        self.assertEqual("https://example.test", submissions[0][0])
        self.assertEqual("standard-pentest", submissions[0][2]["profile_name"])
        self.assertEqual(submissions[0][2]["goal_id"], submissions[0][2]["idempotency_key"])

    def test_untrusted_message_body_is_not_written_to_the_audit_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            acks = []
            dispatcher = self._dispatcher(root, self.FakeGoalControl(), acks)
            result = dispatcher.handle_message(
                user_id="ou_untrusted",
                chat_id="oc_test",
                message_id="m-untrusted",
                text="secret-value-should-not-be-audited",
            )
            audit = dispatcher.audit_path.read_text(encoding="utf-8")

        self.assertEqual({"handled": False, "reason": "untrusted_user"}, result)
        self.assertNotIn("secret-value-should-not-be-audited", audit)
        self.assertEqual([], acks)


class FeishuWebhookIngressTests(unittest.TestCase):
    @staticmethod
    def _post(handler, payload):
        import http.client
        import json
        import threading

        server = __import__("http.server", fromlist=["ThreadingHTTPServer"]).ThreadingHTTPServer(
            ("127.0.0.1", 0), handler
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            body = json.dumps(payload).encode("utf-8")
            connection = http.client.HTTPConnection(
                "127.0.0.1", server.server_address[1], timeout=5
            )
            connection.request(
                "POST", "/", body=body, headers={"Content-Type": "application/json"}
            )
            response = connection.getresponse()
            response_body = json.loads(response.read().decode("utf-8"))
            connection.close()
            return response.status, response_body
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    @staticmethod
    def _text_event(**message_overrides):
        import json

        message = {
            "message_type": "text",
            "message_id": "om_request",
            "chat_id": "oc_test_chat",
            "content": json.dumps({"text": "status"}),
        }
        message.update(message_overrides)
        return {
            "header": {"token": "verify-token"},
            "event": {
                "sender": {"sender_id": {"open_id": "ou_trusted"}},
                "message": message,
            },
        }

    def test_webhook_refuses_non_loopback_bind_without_creating_a_server(self) -> None:
        from feishu_reply_consumer import main

        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            "os.environ",
            {
                "FEISHU_TRUSTED_USERS": "ou_trusted",
                "FEISHU_VERIFICATION_TOKEN": "verify-token-for-loopback-only",
                "FEISHU_APP_ID": "cli_test",
                "FEISHU_APP_SECRET": "app-secret",
            },
            clear=True,
        ), patch("feishu_reply_consumer.ThreadingHTTPServer") as server:
            result = main(
                [
                    "--mode",
                    "webhook",
                    "--listen",
                    "0.0.0.0:9876",
                    "--command-file",
                    str(Path(tmp) / "commands.jsonl"),
                ]
            )

        self.assertEqual(2, result)
        server.assert_not_called()

    def test_webhook_rejects_a_body_over_the_configured_limit(self) -> None:
        import http.client
        import json

        from feishu_reply_consumer import WEBHOOK_MAX_BODY_BYTES, make_webhook_handler

        class UnusedDispatcher:
            def handle_message(self, **kwargs):
                raise AssertionError(f"dispatcher_called:{kwargs}")

        server = __import__("http.server", fromlist=["ThreadingHTTPServer"]).ThreadingHTTPServer(
            ("127.0.0.1", 0), make_webhook_handler(UnusedDispatcher())
        )
        thread = __import__("threading").Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
            connection.putrequest("POST", "/")
            connection.putheader("Content-Type", "application/json")
            connection.putheader("Content-Length", str(WEBHOOK_MAX_BODY_BYTES + 1))
            connection.endheaders()
            response = connection.getresponse()
            body = response.read()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        self.assertEqual(413, response.status)
        self.assertEqual({"error": "request_too_large"}, json.loads(body.decode("utf-8")))

    def test_webhook_requires_a_verification_token_before_creating_a_server(self) -> None:
        from feishu_reply_consumer import main

        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            "os.environ",
            {
                "FEISHU_TRUSTED_USERS": "ou_trusted",
                "FEISHU_APP_ID": "cli_test",
                "FEISHU_APP_SECRET": "app-secret",
            },
            clear=True,
        ), patch("feishu_reply_consumer.ThreadingHTTPServer") as server:
            result = main(
                [
                    "--mode",
                    "webhook",
                    "--listen",
                    "127.0.0.1:9876",
                    "--command-file",
                    str(Path(tmp) / "commands.jsonl"),
                ]
            )

        self.assertEqual(2, result)
        server.assert_not_called()

    def test_webhook_requires_app_credentials_before_creating_a_server(self) -> None:
        from feishu_reply_consumer import main

        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            "os.environ",
            {
                "FEISHU_TRUSTED_USERS": "ou_trusted",
                "FEISHU_VERIFICATION_TOKEN": "verify-token",
            },
            clear=True,
        ), patch("feishu_reply_consumer.ThreadingHTTPServer") as server:
            result = main(
                [
                    "--mode",
                    "webhook",
                    "--command-file",
                    str(Path(tmp) / "commands.jsonl"),
                ]
            )

        self.assertEqual(2, result)
        server.assert_not_called()

    def test_challenge_is_rejected_without_or_with_the_wrong_token(self) -> None:
        from feishu_reply_consumer import make_webhook_handler

        class UnusedDispatcher:
            def handle_message(self, **kwargs):
                raise AssertionError(f"dispatcher_called:{kwargs}")

        handler = make_webhook_handler(UnusedDispatcher(), "verify-token")
        missing_status, missing_body = self._post(
            handler, {"type": "url_verification", "challenge": "challenge-value"}
        )
        wrong_status, wrong_body = self._post(
            handler,
            {"type": "url_verification", "token": "wrong", "challenge": "challenge-value"},
        )

        self.assertEqual((403, {"error": "bad_token"}), (missing_status, missing_body))
        self.assertEqual((403, {"error": "bad_token"}), (wrong_status, wrong_body))

    def test_handler_without_a_configured_token_fails_closed(self) -> None:
        from feishu_reply_consumer import make_webhook_handler

        class UnusedDispatcher:
            def handle_message(self, **kwargs):
                raise AssertionError(f"dispatcher_called:{kwargs}")

        status, body = self._post(
            make_webhook_handler(UnusedDispatcher()),
            {"type": "url_verification", "challenge": "challenge-value"},
        )

        self.assertEqual(503, status)
        self.assertEqual({"error": "verification_token_not_configured"}, body)

    def test_challenge_is_returned_only_after_token_verification(self) -> None:
        from feishu_reply_consumer import make_webhook_handler

        class UnusedDispatcher:
            def handle_message(self, **kwargs):
                raise AssertionError(f"dispatcher_called:{kwargs}")

        status, body = self._post(
            make_webhook_handler(UnusedDispatcher(), "verify-token"),
            {
                "type": "url_verification",
                "token": "verify-token",
                "challenge": "challenge-value",
            },
        )

        self.assertEqual(200, status)
        self.assertEqual({"challenge": "challenge-value"}, body)

    def test_webhook_replies_through_feishu_api_with_sanitized_text(self) -> None:
        from feishu_reply_consumer import make_webhook_handler

        calls = []

        class RecordingDispatcher:
            def handle_message(self, **kwargs):
                calls.append(("dispatch", kwargs))
                return {
                    "handled": True,
                    "reply": (
                        "已完成\n# Penetration Test Report\nreport-sentinel\n"
                        "Authorization: Bearer transport-sentinel"
                    ),
                }

        def reply(message_id, text):
            calls.append(("reply", {"message_id": message_id, "text": text}))

        status, body = self._post(
            make_webhook_handler(
                RecordingDispatcher(), "verify-token", reply_fn=reply
            ),
            self._text_event(),
        )

        self.assertEqual(200, status)
        self.assertEqual("om_request", calls[0][1]["message_id"])
        self.assertEqual("reply", calls[1][0])
        self.assertEqual("om_request", calls[1][1]["message_id"])
        self.assertNotIn("report-sentinel", calls[1][1]["text"])
        self.assertNotIn("transport-sentinel", calls[1][1]["text"])
        self.assertIn("本地保密内容已拦截", calls[1][1]["text"])
        self.assertEqual("sent", body["reply_delivery"])
        self.assertNotIn("report-sentinel", str(body))
        self.assertNotIn("transport-sentinel", str(body))

    def test_missing_message_id_does_not_reach_the_dispatcher(self) -> None:
        from feishu_reply_consumer import make_webhook_handler

        class UnusedDispatcher:
            def handle_message(self, **kwargs):
                raise AssertionError(f"dispatcher_called:{kwargs}")

        status, body = self._post(
            make_webhook_handler(UnusedDispatcher(), "verify-token"),
            self._text_event(message_id=""),
        )

        self.assertEqual(400, status)
        self.assertEqual({"error": "invalid_message_identity"}, body)

    def test_non_text_message_does_not_reach_the_dispatcher(self) -> None:
        from feishu_reply_consumer import make_webhook_handler

        class UnusedDispatcher:
            def handle_message(self, **kwargs):
                raise AssertionError(f"dispatcher_called:{kwargs}")

        status, body = self._post(
            make_webhook_handler(UnusedDispatcher(), "verify-token"),
            self._text_event(message_type="image", content="{}"),
        )

        self.assertEqual(200, status)
        self.assertFalse(body["handled"])
        self.assertEqual("unsupported_message_type", body["reason"])


class FeishuRouteTests(unittest.TestCase):
    @staticmethod
    def _routes():
        return {
            "schema": "FeishuRoutes/v1",
            "routes": {
                "ops_selfcheck": {
                    "chat_id": "oc_1234567890abcdef",
                    "group": "ops",
                }
            },
            "default": "ops_selfcheck",
        }

    def test_unknown_category_never_falls_back_to_the_default_group(self) -> None:
        from notifier import resolve_chat_id

        with self.assertRaisesRegex(RuntimeError, "^no_route_for_category:findnig$"):
            resolve_chat_id("findnig", self._routes())

    def test_route_schema_and_chat_id_are_validated(self) -> None:
        from notifier import resolve_chat_id

        invalid_schema = self._routes()
        invalid_schema["schema"] = "FeishuRoutes/v0"
        with self.assertRaisesRegex(RuntimeError, "^invalid_feishu_routes_schema$"):
            resolve_chat_id("ops_selfcheck", invalid_schema)

        invalid_chat = self._routes()
        invalid_chat["routes"]["ops_selfcheck"]["chat_id"] = "not-a-chat-id"
        with self.assertRaisesRegex(RuntimeError, "^invalid_feishu_chat_id:ops_selfcheck$"):
            resolve_chat_id("ops_selfcheck", invalid_chat)


if __name__ == "__main__":
    unittest.main()
