"""Tests for core.event_log — the append-only unified event stream."""
from __future__ import annotations

import sys
import tempfile
import threading
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "core"))

from core.event_log import EventLog  # noqa: E402


class EventLogTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "sessions" / "s1" / "events.jsonl"
        self.addCleanup(self._tmp.cleanup)

    def test_append_assigns_monotonic_seq(self) -> None:
        log = EventLog(self.path)
        a = log.append("user_message", session_id="s1", turn_id="T-1", text="hi")
        b = log.append("assistant_message", session_id="s1", turn_id="T-1", text="ok")
        self.assertEqual(1, a["seq"])
        self.assertEqual(2, b["seq"])
        self.assertEqual("hi", a["text"])
        self.assertEqual("root", a["agent_id"])
        self.assertEqual("user_message", a["kind"])
        self.assertEqual(2, log.max_seq())

    def test_payload_cannot_clobber_the_envelope(self) -> None:
        """Payload keys matching a *computed* envelope field must not rewrite it.

        ``seq``/``ts`` are not parameters of ``append``, so a handler that emits
        e.g. ``ts=...`` could otherwise overwrite the event's own sequence number
        and break ``since``-based replay.
        """
        log = EventLog(self.path)
        a = log.append("user_message", session_id="s1", text="hi", seq=999, ts=1.0)
        b = log.append("assistant_message", session_id="s1", text="ok", seq=999)
        self.assertEqual(1, a["seq"])
        self.assertEqual(2, b["seq"])
        self.assertNotEqual(1.0, a["ts"])
        self.assertEqual("user_message", log.since(0)[0]["kind"])

    def test_since_returns_only_newer_events(self) -> None:
        log = EventLog(self.path)
        for i in range(5):
            log.append("subtask_progress", note=f"n{i}")
        tail = log.since(3)
        self.assertEqual([4, 5], [e["seq"] for e in tail])

    def test_since_limit_keeps_most_recent(self) -> None:
        log = EventLog(self.path)
        for i in range(20):
            log.append("tool_call", n=i)
        got = log.since(0, limit=3)
        self.assertEqual([18, 19, 20], [e["seq"] for e in got])

    def test_missing_file_is_empty(self) -> None:
        log = EventLog(Path(self._tmp.name) / "nope.jsonl")
        self.assertEqual([], log.since(0))
        self.assertEqual(0, log.max_seq())

    def test_tolerates_truncated_trailing_line(self) -> None:
        log = EventLog(self.path)
        log.append("user_message", text="one")
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write('{"seq": 2, "kind": "assistant_mess')  # torn write
        events = log.since(0)
        self.assertEqual(1, len(events))
        self.assertEqual(1, events[0]["seq"])

    def test_concurrent_appends_have_unique_seq(self) -> None:
        log = EventLog(self.path)

        def worker(tag: str) -> None:
            for i in range(10):
                log.append("tool_result", tag=tag, n=i)

        threads = [threading.Thread(target=worker, args=(f"w{k}",)) for k in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        events = log.since(0, limit=0)
        self.assertEqual(40, len(events))
        self.assertEqual(list(range(1, 41)), [e["seq"] for e in events])


if __name__ == "__main__":
    unittest.main()
