"""Tests for the console job report-back — a finished run closes its own turn."""
from __future__ import annotations

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "core"))

from console import jobs  # noqa: E402
from core.job_registry import JobRecord  # noqa: E402


def _wait(cond, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(0.01)
    return False


class _Registry:
    """Stand-in for ``JobRegistry`` — ``_on_terminal`` only ever calls ``get``."""

    def __init__(self, job: JobRecord) -> None:
        self.job = job

    def get(self, job_id: str):
        return self.job if self.job is not None and self.job.job_id == job_id else None


class _ReportBackCase(unittest.TestCase):
    """Shared setup: a state dir, and both outbound seams pinned shut."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state_dir = Path(self._tmp.name)
        self.session_id = "s1"
        self.prompts: list = []
        self._saved = (dict(jobs._REPORT_STATE), dict(jobs._NOTIFY_STATE),
                       dict(jobs._ENTRIES), dict(jobs.HANDLERS))
        self.addCleanup(self._restore)
        jobs._REPORT_STATE.clear()
        jobs._REPORT_STATE.update({"tried": True, "fn": None})
        jobs._NOTIFY_STATE.clear()
        jobs._NOTIFY_STATE.update({"tried": True, "fn": None})
        jobs._ENTRIES.clear()

    def _restore(self) -> None:
        jobs.shutdown_all(wait=True)
        for live, saved in zip((jobs._REPORT_STATE, jobs._NOTIFY_STATE,
                                jobs._ENTRIES, jobs.HANDLERS), self._saved):
            live.clear()
            live.update(saved)

    # -- helpers -------------------------------------------------------------
    def _with_llm(self, reply) -> None:
        """A fake completion: records the prompt it was given, returns ``reply``."""
        def _complete(system: str, user: str):
            self.prompts.append((system, user))
            return reply

        jobs._REPORT_STATE.clear()
        jobs._REPORT_STATE.update({"tried": True, "fn": _complete})

    def _with_broadcaster(self, sent: list) -> None:
        class _Broadcaster:
            def broadcast_task_terminal(self, target, **kwargs):
                sent.append((target, kwargs))

        jobs._NOTIFY_STATE.clear()
        jobs._NOTIFY_STATE.update({"tried": True, "fn": _Broadcaster()})

    def _blackboard(self, doc=None) -> Path:
        path = self.state_dir / "src-agent-runs" / "SL-1" / "src-blackboard.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        if doc is None:
            doc = {
                "workmem": {"goal": "审计 example.com", "focus": "在 /api/v2 找 IDOR"},
                "intents": [{"status": "completed"}, {"status": "completed"},
                            {"status": "blocked"}],
                "hints": [{"hint": "[sqli] confidence=high evidence=/login?id=1"}],
                "dead_ends": [{"reason": "waf"}],
            }
        path.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
        return path

    def _job(self, *, kind="src_loop", summary_ref="") -> JobRecord:
        return JobRecord(job_id="J-1", session_id=self.session_id, turn_id="T-1",
                         kind=kind, target="https://example.com", summary_ref=str(summary_ref))

    def _terminal(self, job: JobRecord, status="completed") -> None:
        jobs._ENTRIES[str(self.state_dir.resolve())] = {"registry": _Registry(job)}
        jobs._on_terminal(job.job_id, status)

    def _messages(self) -> list:
        log = jobs.get_log(self.state_dir, self.session_id)
        return [e for e in log.tail() if e.get("kind") == "assistant_message"]


class ReportBackTests(_ReportBackCase):
    def test_a_completed_run_reports_back_into_the_conversation(self) -> None:
        self._with_llm("发现 /login?id=1 疑似 SQL 注入(explorer 高置信度),建议人工复核。")
        self._terminal(self._job(summary_ref=self._blackboard()))

        messages = self._messages()
        self.assertEqual(1, len(messages))
        self.assertEqual("J-1", messages[0]["job_id"])
        self.assertIn("SQL 注入", messages[0]["text"])
        # The conclusion has to come from the blackboard, not from a canned line.
        prompt = self.prompts[0][1]
        self.assertIn("[sqli] confidence=high", prompt)
        self.assertIn("审计 example.com", prompt)

    def test_digest_reports_counts_hints_and_focus(self) -> None:
        doc = json.loads(self._blackboard().read_text(encoding="utf-8"))
        digest = jobs._blackboard_digest(doc)
        self.assertIn("审计 example.com", digest)
        self.assertIn("任务 3 个:完成 2、待人工复核 1、死路 1", digest)
        self.assertIn("[sqli] confidence=high", digest)
        self.assertIn("最后的推理焦点:在 /api/v2 找 IDOR", digest)

    def test_digest_is_honest_about_an_empty_blackboard(self) -> None:
        digest = jobs._blackboard_digest({})
        self.assertIn("任务 0 个", digest)
        self.assertIn("发现:无", digest)

    def test_digest_tolerates_junk_shapes(self) -> None:
        digest = jobs._blackboard_digest(
            {"workmem": "not a dict", "intents": [None, "x"], "hints": [{"hint": None}],
             "dead_ends": "nope"})
        self.assertIn("任务 0 个", digest)

    def test_silent_when_the_model_has_nothing_to_say(self) -> None:
        self._with_llm(None)
        self._terminal(self._job(summary_ref=self._blackboard()))
        self.assertEqual(1, len(self.prompts))
        self.assertEqual([], self._messages())

    def test_silent_for_a_kind_that_is_not_a_run(self) -> None:
        self._with_llm("should never be asked")
        self._terminal(self._job(kind="chat_turn", summary_ref=self._blackboard()))
        self.assertEqual([], self.prompts)
        self.assertEqual([], self._messages())

    def test_silent_without_a_summary_ref(self) -> None:
        self._with_llm("should never be asked")
        self._terminal(self._job())
        self.assertEqual([], self.prompts)
        self.assertEqual([], self._messages())

    def test_an_unreadable_blackboard_is_not_fatal(self) -> None:
        self._with_llm("should never be asked")
        cases = [("missing", self.state_dir / "nope.json", None),
                 ("not json", self.state_dir / "junk.json", "<html>oops"),
                 ("not a document", self.state_dir / "list.json", "[]")]
        for label, path, body in cases:
            with self.subTest(label):
                if body is not None:
                    path.write_text(body, encoding="utf-8")
                self._terminal(self._job(summary_ref=path))
        self.assertEqual([], self.prompts)
        self.assertEqual([], self._messages())

    def test_a_failed_run_is_not_reported(self) -> None:
        self._with_llm("should never be asked")
        self._terminal(self._job(summary_ref=self._blackboard()), status="failed")
        self.assertEqual([], self.prompts)
        self.assertEqual([], self._messages())

    def test_the_notification_still_goes_out_when_there_is_no_report(self) -> None:
        sent: list = []
        self._with_broadcaster(sent)
        # No model, so the report is skipped — that must not swallow the notification.
        self._terminal(self._job(summary_ref=self._blackboard()), status="completed")

        self.assertEqual([], self._messages())
        self.assertEqual(1, len(sent))
        target, kwargs = sent[0]
        self.assertEqual("https://example.com", target)
        self.assertEqual("finished", kwargs["status"])
        self.assertTrue(kwargs["report_ready"])

    def test_an_unknown_job_is_ignored(self) -> None:
        self._with_llm("should never be asked")
        jobs._ENTRIES[str(self.state_dir.resolve())] = {"registry": _Registry(None)}
        jobs._on_terminal("J-1", "completed")
        self.assertEqual([], self.prompts)


class ReportBackThroughTheRunnerTests(_ReportBackCase):
    """The wiring itself: runner → notify_fn → the session's event log."""

    def test_a_real_run_closes_the_loop(self) -> None:
        self._with_llm("本轮没有发现。")
        blackboard = self._blackboard()

        def handler(job, ctx):
            ctx.emit("subtask_progress", phase="done", findings=0)
            return {"summary_ref": str(blackboard)}

        jobs.HANDLERS["src_loop"] = handler
        registry = jobs.get_registry(self.state_dir)
        job = registry.create(session_id=self.session_id, turn_id="T-1", kind="src_loop",
                              target="https://example.com")
        jobs.get_runner(self.state_dir).submit(job)

        self.assertTrue(_wait(lambda: (registry.get(job.job_id) or job).status in ("completed", "failed")))
        self.assertEqual("completed", registry.get(job.job_id).status)
        # The status flips before the report is written, so wait on the report itself.
        self.assertTrue(_wait(lambda: len(self._messages()) == 1))
        messages = self._messages()
        self.assertEqual(job.job_id, messages[0]["job_id"])
        self.assertEqual("本轮没有发现。", messages[0]["text"])


if __name__ == "__main__":
    unittest.main()
