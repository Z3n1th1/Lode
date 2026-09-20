"""监听目录:拖进去的文件只算"提议",不是一次授权。

这条入口最容易变成"放文件就是全部授权动作" —— 那样就没有第二个签名了。所以这里
钉的头一条测试就是:文件被收下时**一个 job 都没起**。
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "core"))

from console import jobs as console_jobs  # noqa: E402
from console.intake import scope_pending_preview  # noqa: E402
from console.scope_inbox import INTERVAL_ENV, ScopeInbox, interval_from_env  # noqa: E402


def _document(**overrides) -> dict:
    doc = {
        "program": "nba-public",
        "authorization": "HackerOne managed program, closed scope",
        "allowed_hosts": ["api.nba.com", "cdn.nba.com"],
        "rate_limit": {"requests_per_second": 3},
    }
    doc.update(overrides)
    return doc


class ScopeInboxTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state = Path(self._tmp.name) / "state"
        self.inbox = ScopeInbox(self.state, interval=0.5)
        self.inbox.root.mkdir(parents=True)
        self.addCleanup(console_jobs.shutdown_all)

    def _drop(self, name: str, payload) -> Path:
        path = self.inbox.root / name
        text = payload if isinstance(payload, str) else json.dumps(payload)
        path.write_text(text, encoding="utf-8")
        return path

    def _scan_twice(self) -> dict:
        """一个文件要连续两次看到同样的 size+mtime 才算写完,所以这里扫两轮。"""
        self.inbox.scan_once(now=1_000.0)
        return self.inbox.scan_once(now=1_000.0)

    def test_a_dropped_document_mints_a_card_and_starts_nothing(self) -> None:
        """放文件只是提议 —— 拖进去之后必须有一步确认,而且不能顺手开跑。"""
        self._drop("nba.json", _document())
        report = self._scan_twice()

        self.assertEqual(1, len(report["accepted"]))
        self.assertEqual("nba.json", report["accepted"][0]["file"])
        self.assertEqual(2, report["accepted"][0]["hosts"])
        # 待确认卡在槽里。
        preview = scope_pending_preview(self.state)
        self.assertIsNotNone(preview)
        self.assertEqual(["api.nba.com", "cdn.nba.com"], list(preview.summary["hosts"]))
        # 一个 job 都没有 —— 这条不变量是"这个模块可以读文件"的全部理由。
        self.assertEqual([], console_jobs.get_registry(self.state).list(limit=0))

    def test_the_accepted_file_is_moved_out_of_the_inbox(self) -> None:
        """留在原地的文件会被下一轮再看一遍,那就成了重复铸卡。"""
        path = self._drop("nba.json", _document())
        self._scan_twice()
        self.assertFalse(path.exists())
        self.assertTrue((self.inbox.accepted_dir / "nba.json").is_file())
        self.assertEqual([], self.inbox.candidates())

    def test_a_half_written_file_is_left_alone(self) -> None:
        """拖到一半的文件必须等它不再变化 —— 否则读到的是被截断的 JSON。"""
        path = self._drop("nba.json", _document())
        first = self.inbox.scan_once(now=1_000.0)
        self.assertEqual(["nba.json"], first["waiting"])
        self.assertEqual([], first["accepted"])
        self.assertTrue(path.exists())

        path.write_text(json.dumps(_document(allowed_hosts=["api.nba.com"])), encoding="utf-8")
        second = self.inbox.scan_once(now=1_001.0)
        self.assertEqual(["nba.json"], second["waiting"])   # 尺寸变了,再等一轮
        third = self.inbox.scan_once(now=1_002.0)
        self.assertEqual(1, len(third["accepted"]))
        self.assertEqual(1, third["accepted"][0]["hosts"])

    def test_a_domain_pattern_is_rejected_with_a_reason_on_disk(self) -> None:
        path = self._drop("nba.json", {"authorization": "a", "allowed_domains": ["nba.com"]})
        report = self._scan_twice()

        self.assertEqual([], report["accepted"])
        self.assertEqual(1, len(report["rejected"]))
        self.assertEqual("scope_document_domains_not_allowed", report["rejected"][0]["reason"])
        self.assertIn("nba.com", report["rejected"][0]["detail"])
        # 文件被移走,理由落在它旁边,而且能被 UI 读到。
        self.assertFalse(path.exists())
        self.assertTrue((self.inbox.rejected_dir / "nba.json").is_file())
        reason_file = (self.inbox.rejected_dir / "nba.json.reason.txt").read_text(encoding="utf-8")
        self.assertIn("scope_document_domains_not_allowed", reason_file)
        self.assertEqual("scope_document_domains_not_allowed", self.inbox.rejects()[-1]["reason"])
        self.assertIsNone(scope_pending_preview(self.state))

    def test_a_deferred_document_is_kept_not_rejected(self) -> None:
        """槽被占着时,一份**好**文档不该被丢进 rejected/ —— 它还等着被收下。"""
        self._drop("first.json", _document())
        self._scan_twice()
        second = self._drop("second.json", _document(program="other", allowed_hosts=["x.example.com"]))
        report = self._scan_twice()

        self.assertEqual([], report["accepted"])
        self.assertEqual([], report["rejected"])
        self.assertEqual("pending_intake_exists", report["waiting"][-1]["reason"])
        self.assertTrue(second.exists())
        # 第一份已经被收走了,所以留在原地等的那一份就是它;而且它下一轮会被立刻
        # 再试一次,不用再等两拍建新指纹。
        self.assertEqual(["second.json"], [path.name for path in self.inbox.candidates()])
        self.assertEqual([], self.inbox.rejects())
        # 下一轮它会立刻再试一次(不用重新等两拍),而这个槽仍然被占着。
        again = self.inbox.scan_once(now=9_999.0)
        self.assertEqual([], again["accepted"])
        self.assertEqual("second.json", again["waiting"][-1]["file"])

    def test_an_unreadable_file_is_rejected_not_crashed(self) -> None:
        path = self.inbox.root / "junk.json"
        path.write_bytes(b"\xff\xfe\x00 not utf-8")
        report = self._scan_twice()
        self.assertEqual(1, len(report["rejected"]))
        self.assertEqual("scope_inbox_unreadable", report["rejected"][0]["reason"])

    def test_a_same_named_drop_does_not_overwrite_the_previous_record(self) -> None:
        """同名文件再拖一次不该覆盖上一次的下场 —— 那份记录是证据的一部分。"""
        self._drop("nba.json", {"authorization": "a", "allowed_domains": ["x.com"]})
        self._scan_twice()
        self._drop("nba.json", {"authorization": "a", "allowed_domains": ["y.com"]})
        self._scan_twice()

        self.assertTrue((self.inbox.rejected_dir / "nba.json").is_file())
        self.assertTrue((self.inbox.rejected_dir / "nba.1.json").is_file())
        reasons = [record["detail"] for record in self.inbox.rejects()]
        self.assertEqual(["x.com", "y.com"], reasons)

    def test_no_inbox_directory_means_no_work(self) -> None:
        empty = ScopeInbox(Path(self._tmp.name) / "nothing-here", interval=0.5)
        self.assertEqual({"accepted": [], "rejected": [], "waiting": []}, empty.scan_once())
        self.assertEqual([], empty.rejects())

    def test_the_interval_comes_from_the_environment_and_is_clamped(self) -> None:
        from unittest.mock import patch

        self.assertEqual(5.0, interval_from_env())
        with patch.dict("os.environ", {INTERVAL_ENV: "0.01"}):
            self.assertEqual(0.5, interval_from_env())
        with patch.dict("os.environ", {INTERVAL_ENV: "99999"}):
            self.assertEqual(600.0, interval_from_env())
        with patch.dict("os.environ", {INTERVAL_ENV: "nonsense"}):
            self.assertEqual(5.0, interval_from_env())


if __name__ == "__main__":
    unittest.main()
