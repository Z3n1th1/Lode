"""Tests for SRC chat session lifecycle — lazy creation, listing, prune, delete."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT))
sys.path.insert(0, str(_PROJECT_ROOT / "core"))

import agents.src_chat as sc


class _SessionTestCase(unittest.TestCase):
    def setUp(self) -> None:
        sc._sessions.clear()
        self._tmp = tempfile.TemporaryDirectory()
        self.state = Path(self._tmp.name) / "state"
        (self.state / "src-chat").mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        sc._sessions.clear()
        self._tmp.cleanup()

    def _make(self, session_id: str, *, messages=None, blackboard: bool = False,
              title: str = "") -> Path:
        sess_dir = self.state / "src-chat" / session_id
        sess_dir.mkdir(parents=True, exist_ok=True)
        if messages is not None:
            (sess_dir / "session.json").write_text(json.dumps({
                "schema": "SrcChatSession/v1", "session_id": session_id, "title": title,
                "created_at": 1.0, "last_active": 2.0, "messages": messages, "events": [],
            }), encoding="utf-8")
        if blackboard:
            (sess_dir / "src-blackboard.json").write_text(json.dumps({
                "schema": "SrcBlackboard/v1", "facts": [], "intents": [],
                "dead_ends": [], "hints": [], "claims": [], "events": [],
            }), encoding="utf-8")
        return sess_dir


class LazyCreationTests(_SessionTestCase):
    def test_new_session_does_not_touch_disk(self) -> None:
        chat = self.state / "src-chat"
        before = sorted(p.name for p in chat.iterdir())
        sc._get_or_create_session("", state_dir=self.state)
        self.assertEqual(before, sorted(p.name for p in chat.iterdir()))

    def test_session_materializes_on_first_message(self) -> None:
        sess = sc._get_or_create_session("", state_dir=self.state)
        sess.messages.append({"role": "user", "content": "hi"})
        sess.persist()
        self.assertTrue((self.state / "src-chat" / sess.session_id / "session.json").is_file())

    def test_persist_skips_a_session_with_nothing_to_say(self) -> None:
        sess = sc._get_or_create_session("", state_dir=self.state)
        sess.persist()
        self.assertFalse((self.state / "src-chat" / sess.session_id).exists())


class ListingTests(_SessionTestCase):
    def test_dirs_without_evidence_are_not_listed(self) -> None:
        self._make("src-aaa111111111", messages=[])
        (self.state / "src-chat" / "src-bbb222222222").mkdir()  # stray dir, no files
        self.assertEqual(["src-aaa111111111"],
                         [s["session_id"] for s in sc.list_sessions(self.state)])

    def test_empty_flag_and_turn_count(self) -> None:
        self._make("src-aaa111111111", messages=[{"role": "user", "content": "hi"}])
        self._make("src-bbb222222222", messages=[])
        info = {s["session_id"]: s for s in sc.list_sessions(self.state)}
        self.assertFalse(info["src-aaa111111111"]["empty"])
        self.assertEqual(1, info["src-aaa111111111"]["turns"])
        self.assertTrue(info["src-bbb222222222"]["empty"])

    def test_blackboard_only_dir_is_listed_and_marked_empty(self) -> None:
        self._make("src-scan3333333", messages=[], blackboard=True)
        listed = sc.list_sessions(self.state)
        self.assertEqual(1, len(listed))
        self.assertTrue(listed[0]["empty"])

    def test_pinned_sorts_first(self) -> None:
        self._make("src-aaa111111111", messages=[{"role": "user", "content": "a"}])
        self._make("src-bbb222222222", messages=[{"role": "user", "content": "b"}])
        self.assertTrue(sc.set_session_pinned("src-bbb222222222", True, state_dir=self.state))
        self.assertEqual("src-bbb222222222", sc.list_sessions(self.state)[0]["session_id"])


class RenameDeletePruneTests(_SessionTestCase):
    def test_rename_persists_the_title(self) -> None:
        self._make("src-aaa111111111", messages=[{"role": "user", "content": "hi"}])
        self.assertIsNotNone(sc.rename_session("src-aaa111111111", "越权测试", state_dir=self.state))
        doc = json.loads((self.state / "src-chat" / "src-aaa111111111" / "session.json")
                         .read_text(encoding="utf-8"))
        self.assertEqual("越权测试", doc["title"])

    def test_rename_unknown_session_returns_none(self) -> None:
        self.assertIsNone(sc.rename_session("src-missing0000", "x", state_dir=self.state))

    def test_delete_rejects_bad_ids(self) -> None:
        for bad in ["", "../etc", "src-../../x", "other-abc", "src-abc/def", "src-abc\\x"]:
            self.assertFalse(sc.delete_session(bad, state_dir=self.state), bad)

    def test_delete_removes_the_whole_workspace(self) -> None:
        sess_dir = self._make("src-aaa111111111",
                              messages=[{"role": "user", "content": "hi"}], blackboard=True)
        self.assertTrue(sc.delete_session("src-aaa111111111", state_dir=self.state))
        self.assertFalse(sess_dir.exists())

    def test_prune_removes_only_empty_workless_sessions(self) -> None:
        self._make("src-empty1111111", messages=[])
        self._make("src-talk2222222", messages=[{"role": "user", "content": "hi"}])
        self._make("src-scan3333333", messages=[], blackboard=True)
        (self.state / "src-chat" / "src-stray444444").mkdir()
        result = sc.prune_empty_sessions(self.state)
        self.assertEqual(2, result["removed"])  # empty transcript + stray dir
        self.assertEqual(2, result["kept"])     # real conversation + scan with blackboard
        self.assertEqual(["src-scan3333333", "src-talk2222222"],
                         sorted(p.name for p in (self.state / "src-chat").iterdir()))


if __name__ == "__main__":
    unittest.main()
