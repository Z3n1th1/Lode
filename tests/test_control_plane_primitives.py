"""Control-plane primitives that must stay deterministic and safe."""
from __future__ import annotations

import sys
import json
import tempfile
import unittest
from pathlib import Path


PENTEST_AGENT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PENTEST_AGENT / "core"))
sys.path.insert(0, str(PENTEST_AGENT / "notify"))


class OperationProfileTests(unittest.TestCase):
    def test_strategy_prompt_loads_and_describes_default_behavior(self) -> None:
        from operation_profile import prompt_strategy_selection

        prompt = prompt_strategy_selection()

        self.assertIn("standard-pentest", prompt)
        self.assertIn("红队演练", prompt)


class BroadcasterBindTests(unittest.TestCase):
    def test_bare_ipv6_loopback_is_not_public(self) -> None:
        from broadcaster import Broadcaster

        sent = []
        broadcaster = Broadcaster(
            send_fn=lambda category, text: sent.append((category, text)) or "mock",
        )

        self.assertIsNone(broadcaster.check_bind_address("local-service", "::1"))
        self.assertEqual([], sent)


class BroadcasterLifecycleTests(unittest.TestCase):
    def test_task_terminal_message_distinguishes_timeout_from_success(self) -> None:
        from broadcaster import Broadcaster

        sent = []
        broadcaster = Broadcaster(
            send_fn=lambda category, text: sent.append((category, text)) or "mock",
        )

        record = broadcaster.broadcast_task_terminal(
            "https://example.test",
            task_id="T-001",
            status="timeout",
            elapsed="2小时",
            report_ready=False,
        )

        self.assertEqual("task_terminal", record.kind)
        self.assertEqual(["ops_selfcheck"], record.categories)
        self.assertIn("超时", record.text)
        self.assertNotIn("渗透完成", record.text)
        self.assertEqual("ops_selfcheck", sent[0][0])

    def test_task_progress_uses_a_short_truthful_message_without_endpoint_counts(self) -> None:
        from broadcaster import Broadcaster

        sent = []
        broadcaster = Broadcaster(
            send_fn=lambda category, text: sent.append((category, text)) or "mock",
        )

        record = broadcaster.broadcast_task_progress(
            "https://example.test",
            task_id="T-001",
            elapsed="1分钟",
        )

        self.assertEqual("task_progress", record.kind)
        self.assertIn("仍在执行", record.text)
        self.assertNotIn("已审计接口", record.text)
        self.assertEqual([("ops_selfcheck", record.text)], sent)

    def test_confidential_skill_output_never_reaches_send_or_audit_content(self) -> None:
        from broadcaster import Broadcaster

        sentinel = "REPORT-SENTINEL-8f6c9b"
        sent = []
        with tempfile.TemporaryDirectory() as tmp:
            audit_path = Path(tmp) / "broadcast-audit.jsonl"
            broadcaster = Broadcaster(
                send_fn=lambda category, text: sent.append((category, text)) or "mock",
                audit_path=audit_path,
            )
            record = broadcaster.broadcast_finding(
                "H",
                "F-001",
                "已确认越权",
                f"skill report {sentinel} Authorization: Bearer top-secret-token",
                "https://user:pass@example.test/private?token=secret",
                evidence_ref=f"E:\\private\\{sentinel}\\evidence.json",
            )
            broadcaster.broadcast_finish(
                "https://example.test/private?session=secret",
                elapsed="1分钟",
                key_finding=f"{sentinel} /private/repro",
            )

            audit_text = audit_path.read_text(encoding="utf-8")
            audit_rows = [json.loads(line) for line in audit_text.splitlines()]

        outbound = "\n".join(text for _, text in sent)
        self.assertNotIn(sentinel, outbound)
        self.assertNotIn("top-secret-token", outbound)
        self.assertNotIn("user:pass", outbound)
        self.assertNotIn("?token=", outbound)
        self.assertNotIn(sentinel, audit_text)
        self.assertNotIn("text_preview", audit_rows[0])
        self.assertNotIn("target", audit_rows[0])
        self.assertIn("text_sha256", audit_rows[0])
        self.assertNotIn(sentinel, record.text)


class ConfidentialityBoundaryTests(unittest.TestCase):
    def test_sanitizer_blocks_credentials_raw_http_report_and_local_paths(self) -> None:
        from confidentiality import sanitize_external_text

        source = (
            "token=token-sentinel Authorization: Bearer bearer-sentinel\n"
            "Cookie: sid=cookie-sentinel\n"
            "路径 E:\\private\\report-sentinel.md\n"
            "链接 https://user:pass@example.test/private?id=customer-sentinel\n"
            "POST /admin HTTP/1.1\nHost: example.test\n\nraw-body-sentinel"
        )
        result = sanitize_external_text(source)

        for secret in (
            "token-sentinel",
            "bearer-sentinel",
            "cookie-sentinel",
            "report-sentinel.md",
            "user:pass",
            "customer-sentinel",
            "raw-body-sentinel",
        ):
            self.assertNotIn(secret, result)
        self.assertIn("本地保密内容已拦截", result)

    def test_feishu_payload_keeps_report_and_evidence_local(self) -> None:
        from feishu_notifier import NotifyEvent, build_payload

        sentinel = "EVIDENCE-SENTINEL-62a1"
        payload = build_payload(
            NotifyEvent(
                level="P0",
                title="已确认安全问题",
                target="https://example.test/private?token=secret",
                evidence_ref=f"E:\\reports\\{sentinel}.md",
                body="只发送高层结论",
            )
        )
        text = payload["content"]["text"]

        self.assertNotIn(sentinel, text)
        self.assertNotIn("/private", text)
        self.assertNotIn("token=", text)
        self.assertIn("仅保存在本机", text)


if __name__ == "__main__":
    unittest.main()
