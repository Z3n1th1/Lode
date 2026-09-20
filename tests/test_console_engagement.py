"""Agent 把一份授权文档,钉成一条它能事后复读的记录。

这条记录是"这次跑到底被允许做什么"的唯一书面答案,所以两件事必须成立:它装的是
文档**原文**(派生字段只是给人读的),以及它的 digest 是稳定的 —— 否则同一份文档
重复确认会变成"卡对不上"。
"""
from __future__ import annotations

import dataclasses
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "core"))

from agents.scope_document import parse_scope_document  # noqa: E402
from agents.surface_discovery import SurfaceScope  # noqa: E402
from console import jobs as console_jobs  # noqa: E402
from console.engagement import (  # noqa: E402
    EngagementAuthorizationStore, EngagementStateError, SCHEMA,
    authorization_from_document,
)
from core.intake_state import canonical_digest  # noqa: E402
from core.rate_limit import bucket_key  # noqa: E402


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


def _noop_run(job, ctx):
    """替身:一次确认绝不能真的发流量,测试里也不行。"""
    return {"summary_ref": "test:noop"}


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


class OneHostScopeTests(unittest.TestCase):
    """每台主机只拿到它自己那一台 —— 而主机之外的一切都继承 canonical 解析。"""

    def _scope(self, host: str = "api.nba.com", **overrides):
        document = _document(**overrides)
        return document, console_jobs._scope_from_engagement_document(
            document, host=host, authorization_id="nba-public-abc", run_id="R1",
            engagement="nba-public")

    def test_a_host_cannot_reach_its_siblings(self) -> None:
        """一份文档授权的是"N 台各自可打",不是"N 台合起来构成一张更大的网"。

        折成一台主机是为了让 job.target 有意义:一个覆盖整份清单的 scope 会让每台
        主机的运行都能碰到清单里的其他所有机器。
        """
        _document, scope = self._scope()
        self.assertTrue(scope.check_url("https://api.nba.com/login")[0])
        self.assertFalse(scope.check_url("https://cdn.nba.com/")[0])
        self.assertFalse(scope.check_url("https://other.example.com/")[0])
        self.assertEqual((), scope.allowed_domains)
        # 排除清单是文档给的,仍然生效,而且是它自己的理由码。
        self.assertFalse(scope.check_url("https://cms.nba.com/")[1] != "forbidden_host")

    def test_every_field_except_the_host_axis_equals_from_mapping(self) -> None:
        """防漂移的主测试:主机之外,一个字段都不许被这里重新推导。

        ``_scope_from_confirmed_card`` 就是反面教材 —— 它只搬运 ``forbidden_hosts``,
        授权文档里的方法维度和 body 许可在那条路上直接没了。有人以后想"顺手"在这里
        再算一遍 timeout 或 delay,这条会立刻红。
        """
        document, scope = self._scope()
        base = SurfaceScope.from_mapping(document)
        # 这些字段**应该**不同:前三个是 Console 铸的身份,后三个是主机轴。
        axis = {"program", "authorization", "engagement",
                "allowed_hosts", "allowed_ips", "allowed_domains"}
        for name in axis:
            with self.subTest(axis=name):
                self.assertIn(name, {field.name for field in dataclasses.fields(SurfaceScope)})
        for field in dataclasses.fields(SurfaceScope):
            if field.name in axis:
                continue
            with self.subTest(field=field.name):
                self.assertEqual(getattr(base, field.name), getattr(scope, field.name))

    def test_the_declared_rate_and_capabilities_survive_the_slice(self) -> None:
        _document, scope = self._scope()
        self.assertAlmostEqual(3.0, scope.requests_per_second, places=6)
        self.assertEqual(("GET", "HEAD", "POST"), scope.allowed_methods)
        self.assertIs(True, scope.allow_request_body)
        self.assertEqual(("cms.nba.com",), scope.forbidden)

    def test_the_whole_authorisation_shares_one_budget(self) -> None:
        """N 台主机一个桶:令牌桶是速率那件事的硬盖,不是每个 job 一份。

        这是 c19f156 那个 bug 的形状 —— 每个 job 一个桶,文档写 3 req/s 而程序被
        打了 3×N。
        """
        _document, first = self._scope(host="api.nba.com")
        _document, second = self._scope(host="cdn.nba.com")
        self.assertEqual(bucket_key(first), bucket_key(second))
        self.assertEqual("nba-public", bucket_key(first))

    def test_an_ip_host_matches_on_the_ip_axis(self) -> None:
        """``check_url`` 对 IP 目标只查 ``allowed_ips``,所以 IP 要放进那一栏。"""
        document = _document(allowed_hosts=["93.184.216.34"], allowed_methods=["GET"])
        scope = console_jobs._scope_from_engagement_document(
            document, host="93.184.216.34", authorization_id="a-1", run_id="R1", engagement="e")
        self.assertEqual(("93.184.216.34",), scope.allowed_ips)
        self.assertEqual((), scope.allowed_hosts)
        self.assertTrue(scope.check_url("https://93.184.216.34/")[0])

    def test_the_persisted_record_points_back_at_the_document(self) -> None:
        _document, scope = self._scope()
        doc = console_jobs._scope_document(scope, run_id="SL-1",
                                          authorization_id="nba-public-abc",
                                          authorization_digest="d" * 64)
        self.assertEqual("nba-public-abc", doc["authorization_id"])
        self.assertEqual("d" * 64, doc["authorization_digest"])
        self.assertEqual(scope.engagement, doc["engagement"])


class EngagementRunTests(unittest.TestCase):
    """一次确认 → 每台主机一个 job,共用一个会话与一个预算。"""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        # Cleanups run LIFO, so the temp dir is registered first: 池子必须先停干净,
        # 否则 Windows 不让删还开着的 .lock 文件。
        self.addCleanup(self._tmp.cleanup)
        self.state = Path(self._tmp.name) / "state"
        self.addCleanup(lambda: console_jobs.shutdown_all(wait=True))
        self.record = _record()
        self.written = EngagementAuthorizationStore(self.state).materialize(self.record)
        self.confirmed = {
            "intake_id": "I-1", "authorization": self.record,
            "authorization_digest": self.written["authorization_digest"], "instruction": "hunt nba",
        }

    def _start(self, **overrides):
        with patch.dict(console_jobs.HANDLERS, {console_jobs.ENGAGEMENT_HOST_RUN_KIND: _noop_run}):
            return console_jobs.start_engagement_run(self.state, confirmed=self.confirmed, **overrides)

    def test_each_host_becomes_its_own_job(self) -> None:
        out = self._start()
        self.assertEqual(["api.nba.com", "cdn.nba.com"], out["hosts"])
        self.assertEqual(2, out["created"])
        self.assertFalse(out["reused"])

        jobs = console_jobs.get_registry(self.state).list(limit=0)
        self.assertEqual(2, len(jobs))
        self.assertEqual({"https://api.nba.com/", "https://cdn.nba.com/"},
                         {job.target for job in jobs})
        # 一个会话 + 一个 turn:它们渲染在同一次对话里,一次停止停掉全部。
        self.assertEqual(1, len({job.session_id for job in jobs}))
        self.assertEqual(1, len({job.turn_id for job in jobs}))
        payload = jobs[0].payload
        self.assertEqual("engagement", payload["via"])
        self.assertEqual(self.record["authorization_id"], payload["authorization_id"])
        self.assertEqual(self.written["authorization_digest"], payload["authorization_digest"])
        self.assertEqual(self.record["program"], payload["program"])

    def test_a_replayed_confirmation_does_not_start_second_runs(self) -> None:
        first = self._start()
        second = self._start()
        self.assertEqual(first["job_ids"], second["job_ids"])
        self.assertTrue(second["reused"])
        self.assertEqual(0, second["created"])

    def test_a_partial_fan_out_resumes_without_duplicating(self) -> None:
        """中途崩了再确认一次:已经起了的不能重复起,缺的要补上。

        所以幂等键是 (authorization_id, host) 而不是 intake —— 一次授权可能有 200
        台主机,它们不是一次提交。
        """
        self.record = _record(allowed_hosts=["a.nba.com", "b.nba.com", "c.nba.com"], max_fanout=3)
        self.written = EngagementAuthorizationStore(self.state).materialize(self.record)
        self.confirmed["authorization"] = self.record
        self.confirmed["authorization_digest"] = self.written["authorization_digest"]
        registry = console_jobs.get_registry(self.state)
        # 上一次只起了第一台就崩了的那一瞬间。
        registry.create(session_id="src-prior0001", turn_id="T-prior",
                        kind=console_jobs.ENGAGEMENT_HOST_RUN_KIND, target="https://a.nba.com/",
                        payload={"authorization_id": self.record["authorization_id"], "host": "a.nba.com"})

        out = self._start()
        self.assertEqual(2, out["created"])
        self.assertFalse(out["reused"])
        hosts = [job.payload.get("host") for job in registry.list(limit=0)
                 if job.kind == console_jobs.ENGAGEMENT_HOST_RUN_KIND]
        # 恰好三台:第一台被复用,不是又起了一个。
        self.assertEqual(["a.nba.com", "b.nba.com", "c.nba.com"], sorted(hosts))
        # 续跑接回原来那次对话,不是另开一个。
        self.assertEqual("src-prior0001", out["session_id"])
        self.assertEqual("T-prior", out["turn_id"])

    def test_the_documents_own_cap_decides_how_many_start(self) -> None:
        """程序文档里写了"别抬上限"的时候,那句话是授权的边界。"""
        self.record = _record(allowed_hosts=["a.nba.com", "b.nba.com", "c.nba.com"], max_fanout=2)
        self.written = EngagementAuthorizationStore(self.state).materialize(self.record)
        self.confirmed["authorization"] = self.record
        self.confirmed["authorization_digest"] = self.written["authorization_digest"]
        out = self._start()
        self.assertEqual(2, out["created"])
        self.assertEqual(1, out["skipped"])

    def test_a_host_outside_the_authorisation_never_reaches_the_wire(self) -> None:
        """payload 是持久化记录 —— 不能凭它就发请求,那一台必须真的在那份授权里。"""
        out = self._start()
        registry = console_jobs.get_registry(self.state)
        job = registry.create(session_id="src-evil000001", turn_id="T-evil",
                              kind=console_jobs.ENGAGEMENT_HOST_RUN_KIND,
                              target="https://evil.example.com/",
                              payload={**registry.get(out["job_ids"][0]).payload, "host": "evil.example.com"})
        with self.assertRaises(EngagementStateError):
            console_jobs._handler_engagement_host_run(job, _StubCtx(job))

    def test_a_record_edited_after_confirmation_is_refused(self) -> None:
        out = self._start()
        path = Path(self.written["authorization_ref"])
        record = json.loads(path.read_text(encoding="utf-8"))
        record["hosts"].append("evil.example.com")
        path.write_text(json.dumps(record), encoding="utf-8")

        job = console_jobs.get_registry(self.state).get(out["job_ids"][0])
        with self.assertRaises(EngagementStateError):
            console_jobs._handler_engagement_host_run(job, _StubCtx(job))


class _StubCtx:
    """Just enough JobContext for a handler that must fail before it emits."""

    def __init__(self, job) -> None:
        self.job = job

    def emit(self, *_args, **_kwargs) -> None:
        raise AssertionError("an unauthorised host must fail before the run reaches the wire")


if __name__ == "__main__":
    unittest.main()
