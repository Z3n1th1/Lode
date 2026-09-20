"""Agent 把一份授权文档,钉成一条它能事后复读的记录。

这条记录是"这次跑到底被允许做什么"的唯一书面答案,所以两件事必须成立:它装的是
文档**原文**(派生字段只是给人读的),以及它的 digest 是稳定的 —— 否则同一份文档
重复确认会变成"卡对不上"。
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

from agents.scope_document import parse_scope_document  # noqa: E402
from agents.surface_discovery import SurfaceScope  # noqa: E402
from console.engagement import (  # noqa: E402
    EngagementAuthorizationStore, EngagementStateError, SCHEMA,
    authorization_from_document,
)
from core.intake_state import canonical_digest  # noqa: E402


def _document(**overrides) -> dict:
    doc = {
        "program": "nba-public",
        "authorization": "HackerOne managed program, closed scope",
        "allowed_hosts": ["api.nba.com", "cdn.nba.com"],
        "forbidden_hosts": ["cms.nba.com"],
        "rate_limit": {"requests_per_second": 3},
        "allowed_methods": ["POST"],
        "allow_request_body": True,
        "max_fanout": 4,
    }
    doc.update(overrides)
    return doc


def _record(**overrides) -> dict:
    return authorization_from_document(parse_scope_document(_document(**overrides)), source="paste")


class AuthorizationRecordTests(unittest.TestCase):
    def test_the_record_carries_what_the_document_authorised(self) -> None:
        record = _record()
        self.assertEqual(SCHEMA, record["schema"])
        self.assertEqual(["api.nba.com", "cdn.nba.com"], record["hosts"])
        self.assertEqual(["cms.nba.com"], record["forbidden_hosts"])
        self.assertEqual(["GET", "HEAD", "POST"], record["allowed_methods"])
        self.assertIs(True, record["allow_request_body"])
        self.assertAlmostEqual(3.0, record["requests_per_second"], places=6)
        self.assertEqual(4, record["max_fanout"])
        self.assertEqual("paste", record["source"])

    def test_the_verbatim_document_is_the_record_the_loader_reads(self) -> None:
        """派生字段是给人读的;程序读的是原文,而且走的是同一个 loader。

        这条是"两个授权路径不会走样"的落地方式 —— 记录里那份原文必须自己就能过
        ``from_mapping``,不是一句转述。
        """
        record = _record()
        scope = SurfaceScope.from_mapping(record["document"])
        scope.require_authorization()
        self.assertEqual(("GET", "HEAD", "POST"), scope.allowed_methods)
        self.assertEqual(record["document_digest"], canonical_digest(record["document"]))

    def test_the_id_follows_the_document_not_the_program_name(self) -> None:
        """同一份更新的文档是一份**新的**授权,不是同一份的漂移。

        NBA 那份文档明说"每次跑之前重读 policy_scopes"。按程序名取 id,就会让照政策
        更新过的文档变成"卡对不上",于是产品拒绝开跑 —— 那等于惩罚守规矩的人。
        """
        first = _record()
        same = _record()
        updated = _record(allowed_hosts=["api.nba.com", "new.nba.com"])
        self.assertEqual(first["authorization_id"], same["authorization_id"])
        self.assertNotEqual(first["authorization_id"], updated["authorization_id"])

    def test_a_document_without_a_program_name_still_gets_its_own_identity(self) -> None:
        """没有程序名时 ``from_mapping`` 会回落成 "authorized-program"。

        拿它当桶键,所有这类文档会共用一个桶(方向安全,只是更慢),而且两个互不相干
        的程序会互相限速。身份必须在这里就铸出来。
        """
        def unnamed(host: str) -> dict:
            return authorization_from_document(
                parse_scope_document({"authorization": "a", "allowed_hosts": [host]}), source="upload")

        first, second = unnamed("x.example.com"), unnamed("y.example.com")
        for record in (first, second):
            self.assertNotEqual("authorized-program", record["program"])
            self.assertEqual(record["program"], record["engagement"])
        self.assertNotEqual(first["engagement"], second["engagement"])

    def test_the_record_has_no_timestamp(self) -> None:
        """记录里放不住时间:mtime 留着创建时间就够了。

        放一个 ``created_at`` 进去,同一份文档每次铸出来的 digest 都不同,
        ``materialize`` 的"已存在且必须逐字相同"就永远不成立 —— 重复确认立刻变成
        卡对不上。这是被 digest 逼出来的约束,不是少写一个字段。
        """
        record = _record()
        self.assertNotIn("created_at", record)
        self.assertEqual(canonical_digest(record), canonical_digest(_record()))


class AuthorizationStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = EngagementAuthorizationStore(Path(self._tmp.name))

    def test_writing_twice_yields_the_same_record(self) -> None:
        first = self.store.materialize(_record())
        second = self.store.materialize(_record())
        self.assertEqual(first["authorization_digest"], second["authorization_digest"])
        self.assertTrue(Path(first["authorization_ref"]).is_file())

    def test_re_reading_by_digest_returns_the_record(self) -> None:
        written = self.store.materialize(_record())
        loaded = self.store.load(written["authorization_id"], expected_digest=written["authorization_digest"])
        self.assertEqual(written["authorization_digest"], loaded["authorization_digest"])
        self.assertEqual(["api.nba.com", "cdn.nba.com"], loaded["authorization"]["hosts"])

    def test_a_hand_edited_record_is_a_mismatch_not_a_newer_version(self) -> None:
        """来这里复读的人正要照着它发请求,所以漂移必须失败。"""
        written = self.store.materialize(_record())
        path = Path(written["authorization_ref"])
        record = json.loads(path.read_text(encoding="utf-8"))
        record["hosts"].append("attacker.example.com")
        path.write_text(json.dumps(record), encoding="utf-8")

        with self.assertRaises(EngagementStateError) as ctx:
            self.store.load(written["authorization_id"], expected_digest=written["authorization_digest"])
        self.assertEqual("canonical_authorization_mismatch", str(ctx.exception))

    def test_a_record_whose_document_is_not_an_authorisation_is_refused(self) -> None:
        """记录里的原文要自己过一遍 canonical loader —— 否则这条记录只是一张纸。"""
        record = _record()
        record["document"] = {"program": "nba", "allowed_hosts": ["api.nba.com"]}  # 没有 authorization
        with self.assertRaises(EngagementStateError):
            self.store.materialize(record)

    def test_an_empty_host_list_is_refused(self) -> None:
        record = _record()
        record["hosts"] = []
        with self.assertRaises(EngagementStateError):
            self.store.materialize(record)

    def test_a_missing_record_is_unavailable_not_empty(self) -> None:
        with self.assertRaises(EngagementStateError) as ctx:
            self.store.load("nba-public-nosuchthing")
        self.assertEqual("canonical_authorization_unavailable", str(ctx.exception))

    def test_an_id_that_could_escape_the_directory_is_refused(self) -> None:
        for bad in ("../../etc/passwd", "", "a/b", "x" * 200):
            with self.subTest(bad=bad), self.assertRaises(EngagementStateError):
                self.store.path_for(bad)

    def test_the_record_lives_under_the_state_dir(self) -> None:
        """不进仓库根目录:那是操作员的目录,不是我们的。"""
        written = self.store.materialize(_record())
        self.assertTrue(str(written["authorization_ref"]).startswith(str(Path(self._tmp.name))))


if __name__ == "__main__":
    unittest.main()
