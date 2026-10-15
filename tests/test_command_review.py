"""Command judgment: record first, regex on the complete command, no model."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT))

from core import command_review as C  # noqa: E402
from core import llm_client  # noqa: E402


class ReviewTests(unittest.TestCase):
    def test_query_and_insert_pass(self) -> None:
        for command in (
            "echo lode-ok",
            "print('hi')",
            "whoami",
            "SELECT id FROM users LIMIT 1",
            "INSERT INTO canary VALUES (1)",
            "dir",
            "ls -la",
        ):
            with self.subTest(command=command):
                verdict = C.review(command, record=False)
                self.assertTrue(verdict.allowed, command)

    def test_delete_class_is_intercepted(self) -> None:
        cases = (
            ("rm -rf /tmp/x", "destructive_fs"),
            ("del /f secret.txt", "destructive_fs"),
            ("Remove-Item -Recurse C:\\tmp", "destructive_fs"),
            ("DELETE FROM users", "destructive_sql"),
            ("DROP TABLE orders", "destructive_sql"),
            ("TRUNCATE TABLE audit", "destructive_sql"),
            ("drop database prod", "destructive_sql"),
        )
        for command, rule in cases:
            with self.subTest(command=command):
                verdict = C.review(command, record=False)
                self.assertFalse(verdict.allowed, command)
                self.assertEqual(rule, verdict.rule)

    def test_update_and_dump_are_intercepted(self) -> None:
        cases = (
            ("UPDATE users SET role=1", "mutating_update"),
            ("mysqldump -u root shop", "dump"),
            ("SELECT * FROM t INTO OUTFILE '/tmp/x'", "dump"),
            ("update", "destructive_word"),
            ("del file.txt", "destructive_word"),
        )
        for command, rule in cases:
            with self.subTest(command=command):
                verdict = C.review(command, record=False)
                self.assertFalse(verdict.allowed, command)
                self.assertEqual(rule, verdict.rule)

    def test_chained_delete_is_caught_on_the_complete_command(self) -> None:
        verdict = C.review("echo hello && rm -rf /var/data", record=False)
        self.assertFalse(verdict.allowed)
        self.assertEqual("destructive_fs", verdict.rule)

    def test_empty_command_fails_closed(self) -> None:
        verdict = C.review("  ", record=False)
        self.assertFalse(verdict.allowed)
        self.assertEqual("empty", verdict.rule)

    def test_every_command_is_recorded_before_the_decision(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "command-review.jsonl"
            C.review("echo keep", record=True, log=path)
            C.review("rm -rf /tmp/nope", record=True, log=path)
            rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
        self.assertEqual(2, len(rows))
        self.assertEqual("allowed", rows[0]["decision"])
        self.assertTrue(rows[1]["decision"].startswith("intercepted:"))
        self.assertEqual("rm -rf /tmp/nope", rows[1]["command"])


class InterceptToolCallTests(unittest.TestCase):
    def test_non_shell_tools_are_not_this_gate(self) -> None:
        self.assertIsNone(C.intercept_tool_call("fetch_url", {"url": "https://h.example/"}))

    def test_powershell_delete_is_intercepted_and_not_dispatched(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c.jsonl"
            message = C.intercept_tool_call(
                "run_terminal_command",
                {"command": "Remove-Item C:\\secret"},
                log=path,
            )
        self.assertIsNotNone(message)
        self.assertIn("command_review intercepted", message or "")

    def test_echo_on_a_shell_tool_is_not_intercepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c.jsonl"
            self.assertIsNone(C.intercept_tool_call(
                "bash", {"command": "echo lode-ok"}, log=path))


class ToolLoopHookTests(unittest.TestCase):
    def test_shell_delete_never_reaches_dispatch(self) -> None:
        seen: list[str] = []

        rounds = {"n": 0}

        def complete(messages, *, tools=None, timeout=90.0):  # noqa: ANN001
            rounds["n"] += 1
            if rounds["n"] > 1:
                return {"role": "assistant", "content": "stopped"}
            return {"role": "assistant", "content": "", "tool_calls": [
                {"id": "c1", "type": "function",
                 "function": {"name": "run_terminal_command",
                              "arguments": json.dumps({"command": "rm -rf /tmp/x"})}}
            ]}

        def dispatch(name: str, args: dict) -> str:
            seen.append(name)
            return "ran"

        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {
                "LODE_COMMAND_REVIEW_LOG": str(Path(tmp) / "c.jsonl"),
            }):
                result = llm_client.run_tool_loop(
                    [{"role": "user", "content": "hi"}],
                    tools=[],
                    dispatch=dispatch,
                    complete_fn=complete,
                )
        self.assertEqual([], seen)
        tool_msgs = [m for m in result["messages"] if m.get("role") == "tool"]
        self.assertTrue(tool_msgs)
        self.assertIn("command_review intercepted", tool_msgs[0]["content"])


if __name__ == "__main__":
    unittest.main()
