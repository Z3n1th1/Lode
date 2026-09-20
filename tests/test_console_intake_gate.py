"""The Console's intake gate: preview → confirm → TargetCard, end to end.

The route used to write a ``ProjectIntakeRequest/v1`` file that nothing read, so
these tests are really about the two things that must not come back: a submit that
no consumer ever picks up, and a confirmation that was bound to something other
than what the operator was shown.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock
from unittest.mock import patch

from fastapi.testclient import TestClient

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))
sys.path.insert(0, str(_PROJECT_ROOT / "core"))

from console import jobs as console_jobs  # noqa: E402
from console.app import create_app  # noqa: E402
from console import intake as intake_bridge  # noqa: E402
from core.intake_state import IntakeState, IntakeStateError  # noqa: E402

PASSWORD = "strong-local-password"
SESSION_SECRET = "session-secret-for-test-0123456789"
TARGET = "https://target.example.test"
PROFILE = "standard-pentest"
INSTRUCTION = "look at the login flow only"


def _wait(cond, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(0.02)
    return False


def _noop_run(job, ctx):
    """Stand-in for the real run: a confirmation must never reach the network in tests."""
    return {"summary_ref": "test:noop"}


class _GateCase(unittest.TestCase):
    """A Console app whose TargetCards land in a temp root, never in the repo."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        # Cleanups run LIFO, so the temp dir is registered first: the job pool has
        # to be shut down before Windows lets go of its lock files.
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.state_dir = root / "state"
        self.card_root = root / "cards"
        self.card_root.mkdir()
        patcher = mock.patch.object(intake_bridge, "project_root", return_value=self.card_root)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(console_jobs.shutdown_all)

    def client(self, handlers=None) -> TestClient:
        app = create_app(state_dir=self.state_dir, password=PASSWORD, session_secret=SESSION_SECRET)
        # The runner is built on first use inside the app lifespan, so the patched
        # handlers have to be in place while the client enters.  ``target_run``
        # always starts stubbed: confirming starts a run now, and no test may
        # reach the network.
        resolved = {"target_run": _noop_run, **(handlers or {})}
        with patch.dict(console_jobs.HANDLERS, resolved):
            client = TestClient(app)
            client.__enter__()
        self.addCleanup(client.__exit__, None, None, None)
        self.assertEqual(204, client.post("/api/v1/session", json={"password": PASSWORD}).status_code)
        return client

    def confirm(self, client: TestClient, preview: dict, **extra) -> dict:
        body = {"intake_id": preview["intake_id"], "options_digest": preview["options_digest"], **extra}
        return client.post("/api/v1/project/intake/confirm", json=body)

    @staticmethod
    def payload(**overrides) -> dict:
        body = {
            "target_url": TARGET,
            "instruction": INSTRUCTION,
            "engagement_profile": PROFILE,
            "toggles": {"asset_inventory": True, "intel": True},
        }
        body.update(overrides)
        return body

    def submit(self, client: TestClient, **overrides) -> dict:
        resp = client.post("/api/v1/project/intake", json=self.payload(**overrides))
        self.assertEqual(200, resp.status_code, resp.text)
        return resp.json()

    def card_path(self, target_id: str) -> Path:
        return self.card_root / "ai-pentest-evidence" / "projects" / target_id / "target.yaml"


class IntakeGateTests(_GateCase):
    def test_preview_then_confirm_writes_the_target_card(self) -> None:
        client = self.client()

        preview = self.submit(client)
        self.assertEqual("preview", preview["status"])
        self.assertTrue(preview["intake_id"].startswith("I-"))
        self.assertEqual("target.example.test", preview["canonical_host"])
        self.assertEqual(64, len(preview["options_digest"]))
        # The switches the operator flipped are inside the digest binding.
        self.assertTrue(preview["options"]["asset_inventory"]["enabled"])
        self.assertFalse(preview["options"]["nuclei"]["enabled"])
        # A preview executes nothing: no card yet.
        self.assertFalse(list(self.card_root.rglob("target.yaml")))

        pending = client.get("/api/v1/project/intake/pending").json()
        self.assertEqual(preview["intake_id"], pending["preview"]["intake_id"])
        self.assertGreater(pending["ttl_seconds"], 0)
        queue = client.get("/api/v1/project/intakes").json()
        self.assertEqual(preview["intake_id"], queue["intakes"][0]["intake_id"])
        # The ledger is readable, so an empty queue means "nothing pending" rather
        # than "the file is gone" — the two used to look identical.
        self.assertEqual("available", queue["status"])

        confirmed = client.post("/api/v1/project/intake/confirm", json={
            "intake_id": preview["intake_id"], "options_digest": preview["options_digest"],
        })
        self.assertEqual(200, confirmed.status_code, confirmed.text)
        result = confirmed.json()
        self.assertEqual("confirmed", result["status"])
        self.assertEqual(preview["instruction"], result["instruction"])

        card_file = self.card_path(result["target_id"])
        self.assertTrue(card_file.is_file())
        self.assertEqual(f"ai-pentest-evidence/projects/{result['target_id']}/target.yaml",
                         result["target_card_ref"])
        card = json.loads(card_file.read_text(encoding="utf-8"))
        self.assertEqual("TargetCard/v1", card["schema"])
        self.assertEqual(["target.example.test"], card["scope"]["allowed_hosts"])
        # The queue drains the moment the preview stops being confirmable.
        drained = client.get("/api/v1/project/intakes").json()
        self.assertEqual([], drained["intakes"])
        self.assertEqual("available", drained["status"])
        self.assertIsNone(client.get("/api/v1/project/intake/pending").json()["preview"])

    def test_confirmation_must_match_what_was_shown(self) -> None:
        client = self.client()
        preview = self.submit(client)

        wrong_digest = client.post("/api/v1/project/intake/confirm", json={
            "intake_id": preview["intake_id"], "options_digest": "0" * 64,
        })
        self.assertEqual(409, wrong_digest.status_code)
        self.assertEqual("intake_confirmation_binding_mismatch", wrong_digest.json()["detail"])

        wrong_id = client.post("/api/v1/project/intake/confirm", json={
            "intake_id": "I-deadbeef", "options_digest": preview["options_digest"],
        })
        self.assertEqual(409, wrong_id.status_code)
        # A refused confirmation must not consume the preview.
        self.assertIsNotNone(client.get("/api/v1/project/intake/pending").json()["preview"])

        ok = client.post("/api/v1/project/intake/confirm", json={
            "intake_id": preview["intake_id"], "options_digest": preview["options_digest"],
        })
        self.assertEqual(200, ok.status_code, ok.text)

        # A retried confirm (double click, replayed POST) returns the same card.
        retry = client.post("/api/v1/project/intake/confirm", json={
            "intake_id": preview["intake_id"], "options_digest": preview["options_digest"],
        })
        self.assertEqual(200, retry.status_code, retry.text)
        self.assertEqual(ok.json()["target_id"], retry.json()["target_id"])
        self.assertEqual(ok.json()["target_card_digest"], retry.json()["target_card_digest"])

    def test_second_target_while_one_is_pending_conflicts_until_discarded(self) -> None:
        client = self.client()
        first = self.submit(client)

        conflict = client.post("/api/v1/project/intake", json=self.payload(target_url="https://other.example.test"))
        self.assertEqual(409, conflict.status_code, conflict.text)
        body = conflict.json()
        self.assertEqual("pending_intake_exists", body["detail"])
        # The conflict is actionable: it carries the preview that is in the way.
        self.assertEqual(first["intake_id"], body["pending"]["intake_id"])

        # Resubmitting the identical request is idempotent, not a conflict.
        same = self.submit(client)
        self.assertEqual(first["intake_id"], same["intake_id"])

        self.assertTrue(client.post("/api/v1/project/intake/discard").json()["discarded"])
        self.assertFalse(client.post("/api/v1/project/intake/discard").json()["discarded"])
        second = self.submit(client, target_url="https://other.example.test")
        self.assertNotEqual(first["intake_id"], second["intake_id"])

    def test_the_gate_refuses_what_it_cannot_honour(self) -> None:
        client = self.client()

        brute = client.post("/api/v1/project/intake", json=self.payload(
            toggles={"scan_enabled": True, "brute": {"enabled": True, "password": True}}
        ))
        self.assertEqual(400, brute.status_code)
        self.assertEqual("brute_force_out_of_scope", brute.json()["detail"])

        empty = client.post("/api/v1/project/intake", json=self.payload(instruction="   "))
        self.assertEqual(400, empty.status_code)
        self.assertEqual("empty_instruction", empty.json()["detail"])

        private = client.post("/api/v1/project/intake", json=self.payload(target_url="http://127.0.0.1/admin"))
        self.assertEqual(400, private.status_code)
        self.assertEqual("invalid_target", private.json()["detail"])

        unknown_profile = client.post("/api/v1/project/intake", json=self.payload(engagement_profile="nope"))
        self.assertEqual(400, unknown_profile.status_code)
        self.assertEqual("invalid_profile", unknown_profile.json()["detail"])
        # Nothing above may have left a preview or a card behind.
        self.assertIsNone(client.get("/api/v1/project/intake/pending").json()["preview"])
        self.assertFalse(list(self.card_root.rglob("target.yaml")))

    def test_intake_routes_still_require_a_session(self) -> None:
        app = create_app(state_dir=self.state_dir, password=PASSWORD, session_secret=SESSION_SECRET)
        with TestClient(app) as client:
            for method, path, body in (
                ("POST", "/api/v1/project/intake", self.payload()),
                ("POST", "/api/v1/project/intake/confirm", {"intake_id": "I-1", "options_digest": "0" * 64}),
                ("POST", "/api/v1/project/intake/discard", None),
                ("GET", "/api/v1/project/intake/pending", None),
                ("GET", "/api/v1/project/intakes", None),
            ):
                with self.subTest(path=path):
                    self.assertEqual(401, client.request(method, path, json=body).status_code)


class IntakeRunTests(_GateCase):
    """确认即开跑:卡落盘之后才起任务,而且跑的是卡上那一份 scope。"""

    def test_confirm_starts_the_run_that_streams_into_its_own_session(self) -> None:
        seen: list = []

        def fake_run(job, ctx):
            seen.append(job)
            ctx.emit("subtask_progress", phase="autopilot")
            return {"summary_ref": "test:fake"}

        client = self.client({"target_run": fake_run})
        preview = self.submit(client)
        body = self.confirm(client, preview).json()

        run = body["run"]
        self.assertTrue(run["session_id"].startswith("src-"))
        self.assertTrue(run["job_id"])
        self.assertFalse(run["reused"])

        # The run streams into that session's log, which is what the conversation
        # view reads — the operator can watch it without a second UI path.
        self.assertTrue(_wait(lambda: client.get(
            f"/api/v1/chat/sessions/{run['session_id']}/events").json()["max_seq"] >= 2))
        events = client.get(f"/api/v1/chat/sessions/{run['session_id']}/events").json()["events"]
        self.assertEqual(["subtask_started", "subtask_progress", "subtask_finished"],
                         [event["kind"] for event in events])
        self.assertEqual("target_run", events[0]["job_kind"])
        self.assertEqual(TARGET, events[0]["target"])
        self.assertEqual(INSTRUCTION, events[0]["title"])

        # The job carries the card binding, so the handler re-reads the exact
        # object the operator confirmed instead of re-deriving a scope.
        jobs = client.get(f"/api/v1/jobs?session_id={run['session_id']}").json()["jobs"]
        self.assertEqual(1, len(jobs))
        self.assertEqual("target_run", jobs[0]["kind"])
        self.assertEqual("console_intake", jobs[0]["payload"]["via"])
        self.assertEqual(preview["intake_id"], jobs[0]["payload"]["intake_id"])
        self.assertEqual(body["target_card_ref"], jobs[0]["payload"]["target_card_ref"])
        self.assertEqual(body["target_card_digest"], jobs[0]["payload"]["target_card_digest"])
        self.assertTrue(_wait(lambda: seen and seen[0].job_id == run["job_id"]))

    def test_a_replayed_confirm_does_not_start_a_second_run(self) -> None:
        client = self.client()
        preview = self.submit(client)
        first = self.confirm(client, preview).json()
        second = self.confirm(client, preview).json()

        self.assertEqual(first["run"]["job_id"], second["run"]["job_id"])
        self.assertEqual(first["run"]["session_id"], second["run"]["session_id"])
        self.assertTrue(second["run"]["reused"])
        jobs = client.get("/api/v1/jobs?limit=200").json()["jobs"]
        self.assertEqual(1, len([job for job in jobs if job["kind"] == "target_run"]))

    def test_run_into_an_existing_session_is_allowed(self) -> None:
        client = self.client()
        preview = self.submit(client)
        body = self.confirm(client, preview, session_id="src-existing01").json()
        self.assertEqual("src-existing01", body["run"]["session_id"])

    def test_confirm_can_build_the_card_without_running(self) -> None:
        client = self.client()
        preview = self.submit(client)
        body = self.confirm(client, preview, run=False).json()
        self.assertIsNone(body["run"])
        self.assertIn("未开跑", body["note"])
        self.assertTrue(self.card_path(body["target_id"]).is_file())
        self.assertEqual([], client.get("/api/v1/jobs").json()["jobs"])

    def test_a_bad_session_id_is_refused_before_anything_runs(self) -> None:
        client = self.client()
        preview = self.submit(client)
        resp = self.confirm(client, preview, session_id="../../etc/passwd")
        self.assertEqual(400, resp.status_code, resp.text)
        self.assertEqual("invalid_session_id", resp.json()["detail"])
        # The card is already on disk by then — that is the ordering, not a bug.
        self.assertTrue(list(self.card_root.rglob("target.yaml")))

    def test_the_run_scope_is_exactly_the_confirmed_card(self) -> None:
        card = {
            "schema": "TargetCard/v1",
            "target_id": "t-1",
            "scope": {"allowed_hosts": ["target.example.test"], "forbidden_hosts": ["forbidden.example.test"]},
        }
        scope = console_jobs._scope_from_confirmed_card(
            card, target_id="t-1", run_id="SL-1", engagement="turn-T-1", delay=0.5)

        self.assertEqual("confirmed_target_card:t-1", scope.authorization)
        # No registrable-domain widening: only the host on the card.
        self.assertTrue(scope.check_url("https://target.example.test/login")[0])
        self.assertFalse(scope.check_url("https://api.target.example.test/")[0])
        self.assertFalse(scope.check_url("https://other.example.test/")[0])
        self.assertFalse(scope.check_url("https://forbidden.example.test/")[0])
        # 预算身份和节奏都由调用方给:这条路径以前落在 dataclass 默认值上,和手打
        # URL 那条路(0.5)是两个速率。
        self.assertEqual("turn-T-1", scope.engagement)
        self.assertEqual(0.5, scope.delay_seconds)

    def test_a_card_that_changed_after_confirmation_is_refused(self) -> None:
        client = self.client()
        preview = self.submit(client)
        body = self.confirm(client, preview).json()

        card_file = self.card_path(body["target_id"])
        card = json.loads(card_file.read_text(encoding="utf-8"))
        card["scope"]["allowed_hosts"] = ["target.example.test", "extra.example.test"]
        card_file.write_text(json.dumps(card), encoding="utf-8")

        job = console_jobs.get_registry(self.state_dir).create(
            session_id="src-widened001", kind="target_run", target=TARGET, payload={
                "target_id": body["target_id"],
                "target_card_ref": body["target_card_ref"],
                "target_card_digest": body["target_card_digest"],
            },
        )
        with self.assertRaises(IntakeStateError):
            console_jobs._handler_target_run(job, _StubCtx(job))


class _StubCtx:
    """Just enough JobContext for a handler that should fail before it emits."""

    def __init__(self, job) -> None:
        self.job = job

    def emit(self, *_args, **_kwargs) -> None:
        raise AssertionError("an invalid card must fail before the run reaches the wire")


class IntakeOptionsTests(unittest.TestCase):
    """Every switch the dialog offers has to reach the digest, or it was a lie."""

    def test_every_offered_toggle_moves_its_option(self) -> None:
        from console.deps import _INTAKE_TOGGLE_KEYS

        for toggle in intake_bridge.TOGGLE_OPTIONS:
            self.assertIn(toggle, _INTAKE_TOGGLE_KEYS, f"{toggle} is not a known toggle")

        options = intake_bridge.intake_options({key: True for key in intake_bridge.TOGGLE_OPTIONS})
        for toggle, option_key in intake_bridge.TOGGLE_OPTIONS.items():
            with self.subTest(toggle=toggle):
                self.assertIs(options[option_key]["enabled"], True)

        off = intake_bridge.intake_options(None)
        self.assertTrue(all(not group["enabled"] for key, group in off.items()
                            if key != "brute" and isinstance(group, dict)))

    def test_an_unknown_option_key_is_a_loud_failure(self) -> None:
        with mock.patch.dict(intake_bridge.TOGGLE_OPTIONS, {"scan_enabled": "no_such_option"}):
            with self.assertRaises(IntakeStateError):
                intake_bridge.intake_options({"scan_enabled": True})


class GatePrimitiveTests(unittest.TestCase):
    """The two additions the Console needed from the gate itself."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.now = 1_000.0
        self.state = IntakeState(Path(self._tmp.name) / "intakes.jsonl",
                                 now_fn=lambda: self.now, ttl_seconds=60)
        self.preview = self.state.create_preview(
            target=TARGET, instruction=INSTRUCTION, profile_name=PROFILE, goal_id="g1",
            user_id="u1", chat_id="c1", message_id="m1",
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_options_participate_in_the_preview_binding(self) -> None:
        from core.intake_state import default_options

        other = self.state.create_preview(
            target="https://elsewhere.example.test", instruction=INSTRUCTION,
            profile_name=PROFILE, goal_id="g1", user_id="u2", chat_id="c2", message_id="m2",
            options={**default_options(), "asset_inventory": {"enabled": True, "mode": "requested"}},
        )
        self.assertNotEqual(self.preview.options_digest, other.options_digest)

        # Flipping a switch in the stored log, without recomputing the digest, must
        # invalidate the preview rather than silently widen what was confirmed.
        ledger = Path(self._tmp.name) / "intakes.jsonl"
        lines = []
        for line in ledger.read_text(encoding="utf-8").splitlines():
            event = json.loads(line)
            if event.get("event") == "preview_created":
                event["preview"]["options"]["nuclei"] = {"enabled": True, "mode": "requested"}
            lines.append(json.dumps(event, ensure_ascii=False))
        ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.assertIsNone(IntakeState(ledger).pending(user_id="u1", chat_id="c1"))

    def test_discard_pending_writes_the_preview_expired_event(self) -> None:
        self.assertTrue(self.state.discard_pending(user_id="u1", chat_id="c1"))
        self.assertFalse(self.state.discard_pending(user_id="u1", chat_id="c1"))
        self.assertIsNone(self.state.pending(user_id="u1", chat_id="c1"))
        events = [json.loads(line) for line in (Path(self._tmp.name) / "intakes.jsonl").read_text().splitlines()]
        self.assertEqual(["preview_created", "preview_expired"], [e["event"] for e in events])
        # Another reader sees the same state, replayed from the log alone.
        self.assertIsNone(IntakeState(Path(self._tmp.name) / "intakes.jsonl").pending(user_id="u1", chat_id="c1"))

    def test_expired_preview_cannot_be_confirmed(self) -> None:
        from core.intake_state import target_card_from_preview

        self.now += 61
        self.assertIsNone(self.state.pending(user_id="u1", chat_id="c1"))
        with self.assertRaises(IntakeStateError):
            self.state.consume_confirmation(
                user_id="u1", chat_id="c1", message_id="m1", intake_id=self.preview.intake_id,
                options_digest=self.preview.options_digest,
                target_card=target_card_from_preview(self.preview),
            )


class EngagementRouteTests(_GateCase):
    """.一份授权文档从 HTTP 入口走到底:预览 → 确认 → 每台主机一个 job。

    三个入口(粘贴/上传/监听目录)共用这条链,所以这里测的是那条链本身,而不是
    某一个入口的便利写法。
    """

    DOC = {
        "program": "nba-public",
        "authorization": "HackerOne managed program, closed scope",
        "allowed_hosts": ["api.nba.com", "cdn.nba.com"],
        "forbidden_hosts": ["cms.nba.com"],
        "rate_limit": {"requests_per_second": 3},
        "max_fanout": 30,
    }

    def _preview(self, client: TestClient, **overrides) -> dict:
        body = {"text": json.dumps(self.DOC), **overrides}
        resp = client.post("/api/v1/project/engagement/preview", json=body)
        self.assertEqual(200, resp.status_code, resp.text)
        return resp.json()

    def test_preview_then_confirm_starts_one_job_per_host(self) -> None:
        client = self.client({"engagement_host_run": _noop_run})
        preview = self._preview(client)

        self.assertEqual("preview", preview["status"])
        self.assertTrue(preview["intake_id"].startswith("I-"))
        self.assertEqual(["api.nba.com", "cdn.nba.com"], preview["summary"]["hosts"])
        self.assertEqual(30, preview["summary"]["max_fanout"])
        self.assertAlmostEqual(3.0, preview["summary"]["requests_per_second"], places=6)
        # 确认前什么都还没有:没有授权记录,也没有 job。
        self.assertEqual([], client.get("/api/v1/jobs").json()["jobs"])
        self.assertFalse(list(self.card_root.rglob("authorization.json")))

        # 一个槽两种形状:文档pending 时目标那一栏是空的。
        pending = client.get("/api/v1/project/intake/pending").json()
        self.assertIsNone(pending["preview"])
        self.assertEqual(preview["intake_id"], pending["scope_preview"]["intake_id"])

        confirmed = client.post("/api/v1/project/engagement/confirm", json={
            "intake_id": preview["intake_id"], "options_digest": preview["options_digest"]})
        self.assertEqual(200, confirmed.status_code, confirmed.text)
        body = confirmed.json()
        self.assertEqual("confirmed", body["status"])
        self.assertEqual(2, body["run"]["launched"])
        self.assertEqual(0, body["run"]["skipped"])
        self.assertEqual(2, body["run"]["created"])
        self.assertTrue(body["authorization_ref"].endswith(".json"))
        self.assertIn("2 个任务", body["note"])

        jobs = [job for job in client.get("/api/v1/jobs?limit=200").json()["jobs"]
                if job["kind"] == "engagement_host_run"]
        self.assertEqual(2, len(jobs))
        self.assertEqual({"https://api.nba.com/", "https://cdn.nba.com/"}, {job["target"] for job in jobs})
        self.assertEqual(preview["intake_id"], jobs[0]["payload"]["intake_id"])

        # 确认之后槽就空了,而且重放不会起第二批。
        self.assertIsNone(client.get("/api/v1/project/intake/pending").json()["scope_preview"])
        replay = client.post("/api/v1/project/engagement/confirm", json={
            "intake_id": preview["intake_id"], "options_digest": preview["options_digest"]})
        self.assertEqual(200, replay.status_code, replay.text)
        self.assertTrue(replay.json()["run"]["reused"])
        self.assertEqual(2, len([job for job in client.get("/api/v1/jobs?limit=200").json()["jobs"]
                                 if job["kind"] == "engagement_host_run"]))

    def test_a_domain_pattern_is_refused_and_the_entries_are_named(self) -> None:
        """域模式授权的是整片没看过的子域,所以这条入口不收 —— 而且要说是哪几个。"""
        client = self.client({"engagement_host_run": _noop_run})
        resp = client.post("/api/v1/project/engagement/preview", json={
            "text": json.dumps({"authorization": "a", "allowed_domains": ["nba.com", "wnba.com"]})})
        self.assertEqual(400, resp.status_code, resp.text)
        self.assertEqual("scope_document_domains_not_allowed", resp.json()["detail"])
        self.assertIn("nba.com", resp.json()["items"])
        self.assertIsNone(client.get("/api/v1/project/intake/pending").json()["scope_preview"])

    def test_prose_is_not_a_document_and_says_so(self) -> None:
        client = self.client({"engagement_host_run": _noop_run})
        resp = client.post("/api/v1/project/engagement/preview",
                           json={"text": "看看这个 " + json.dumps(self.DOC)})
        self.assertEqual(400, resp.status_code, resp.text)
        self.assertEqual("scope_document_not_recognised", resp.json()["detail"])

    def test_an_empty_body_is_refused_before_the_gate(self) -> None:
        client = self.client({"engagement_host_run": _noop_run})
        resp = client.post("/api/v1/project/engagement/preview", json={"text": "   "})
        self.assertEqual(400, resp.status_code, resp.text)
        self.assertEqual("scope_document_required", resp.json()["detail"])

    def test_a_bad_binding_is_a_conflict(self) -> None:
        client = self.client({"engagement_host_run": _noop_run})
        preview = self._preview(client)
        resp = client.post("/api/v1/project/engagement/confirm",
                           json={"intake_id": preview["intake_id"], "options_digest": "0" * 64})
        self.assertEqual(409, resp.status_code, resp.text)
        # 被拒的确认不能吃掉预览。
        self.assertIsNotNone(client.get("/api/v1/project/intake/pending").json()["scope_preview"])

    def test_discard_clears_the_document_slot(self) -> None:
        client = self.client({"engagement_host_run": _noop_run})
        self._preview(client)
        self.assertTrue(client.post("/api/v1/project/engagement/discard").json()["discarded"])
        self.assertFalse(client.post("/api/v1/project/engagement/discard").json()["discarded"])
        self.assertIsNone(client.get("/api/v1/project/intake/pending").json()["scope_preview"])

    def test_a_target_and_a_document_cannot_be_pending_at_once(self) -> None:
        """一格只放一样东西 —— 但也不能静默把操作员手上那张卡换掉。"""
        client = self.client({"engagement_host_run": _noop_run})
        preview = self._preview(client)
        conflict = client.post("/api/v1/project/intake", json=self.payload())
        self.assertEqual(409, conflict.status_code, conflict.text)
        self.assertEqual("pending_intake_exists", conflict.json()["detail"])
        # 挡路的是一份文档,不是一张目标卡 —— 说清楚,操作员才知道该放弃什么。
        self.assertEqual("document", conflict.json()["pending_kind"])
        self.assertEqual(preview["intake_id"], conflict.json()["pending"]["intake_id"])

    def test_the_documents_own_cap_limits_the_run(self) -> None:
        client = self.client({"engagement_host_run": _noop_run})
        preview = self._preview(client, text=json.dumps({**self.DOC,
                                                         "allowed_hosts": ["a.nba.com", "b.nba.com", "c.nba.com"],
                                                         "max_fanout": 2}))
        body = client.post("/api/v1/project/engagement/confirm", json={
            "intake_id": preview["intake_id"], "options_digest": preview["options_digest"]}).json()
        self.assertEqual(2, body["run"]["launched"])
        self.assertEqual(1, body["run"]["skipped"])
        self.assertIn("1 台超出", body["note"])

    def test_the_pending_endpoint_reports_inbox_refusals(self) -> None:
        """拖进去没反应是最糟的反馈 —— 理由必须能被 UI 读到。"""
        from console import scope_inbox

        # 监听循环本身也在扫这个目录,所以把间隔钉死,让这一轮手动扫描是唯一的动作。
        with patch.dict(os.environ, {scope_inbox.INTERVAL_ENV: "600"}):
            client = self.client({"engagement_host_run": _noop_run})
        inbox = scope_inbox.ScopeInbox(self.state_dir)
        inbox.root.mkdir(parents=True, exist_ok=True)
        (inbox.root / "bad.json").write_text(
            json.dumps({"authorization": "a", "allowed_domains": ["nba.com"]}), encoding="utf-8")
        inbox.scan_once()
        inbox.scan_once()

        body = client.get("/api/v1/project/intake/pending").json()
        self.assertEqual("scope_document_domains_not_allowed", body["scope_rejects"][-1]["reason"])
        self.assertIn("nba.com", body["scope_rejects"][-1]["detail"])
        self.assertIsNone(body["scope_preview"])

    def test_the_engagement_routes_require_a_session(self) -> None:
        app = create_app(state_dir=self.state_dir, password=PASSWORD, session_secret=SESSION_SECRET)
        with TestClient(app) as client:
            for method, path, body in (
                ("POST", "/api/v1/project/engagement/preview", {"text": "{}"}),
                ("POST", "/api/v1/project/engagement/confirm",
                 {"intake_id": "I-1", "options_digest": "0" * 64}),
                ("POST", "/api/v1/project/engagement/discard", None),
            ):
                with self.subTest(path=path):
                    self.assertEqual(401, client.request(method, path, json=body).status_code)


class ScopePreviewGateTests(unittest.TestCase):
    """授权文档和单个目标共用**一个**待确认槽,但各走各的消费口。

    这条边界值得单独钉:一个槽意味着"现在挂着什么"只有一处说了算,而两个消费口
    意味着一条被篡改的文档线不会变成一次目标确认 —— 失败方向必须是"什么都不跑"。
    """

    DOCUMENT = {
        "program": "nba-public",
        "authorization": "HackerOne managed program",
        "allowed_hosts": ["api.nba.com", "cdn.nba.com"],
        "forbidden_hosts": ["cms.nba.com"],
        "rate_limit": {"requests_per_second": 3},
    }

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.now = 1_000.0
        self.path = Path(self._tmp.name) / "intakes.jsonl"
        self.state = IntakeState(self.path, now_fn=lambda: self.now, ttl_seconds=60)
        self.summary = {
            "program": "nba-public", "hosts": ["api.nba.com", "cdn.nba.com"],
            "forbidden_hosts": ["cms.nba.com"], "max_fanout": 30,
            "requests_per_second": 3.0, "allowed_methods": ["GET", "HEAD"],
            "allow_request_body": False,
        }

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _preview(self, **overrides):
        return self.state.create_scope_preview(
            document=dict(self.DOCUMENT), summary=dict(self.summary),
            instruction="run the nba scope", source="paste",
            user_id="u1", chat_id="c1", message_id="m1", **overrides,
        )

    def _rewrite_ledger(self, mutate) -> None:
        lines = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            event = json.loads(line)
            mutate(event)
            lines.append(json.dumps(event, ensure_ascii=False))
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    @staticmethod
    def _reread(path, now):
        """第二个读者:同一个时钟,否则"过期"会替"被篡改"把测试蒙过去。"""
        return IntakeState(path, now_fn=lambda: now)

    def _record(self) -> dict:
        return {"schema": "EngagementAuthorization/v1", "authorization_id": "nba-public-abc",
                "document": dict(self.DOCUMENT), "hosts": list(self.summary["hosts"])}

    def test_a_document_preview_round_trips_through_the_ledger(self) -> None:
        preview = self._preview()
        self.assertTrue(preview.intake_id.startswith("I-"))
        self.assertEqual(2, preview.host_count)

        # Another reader sees the same thing, replayed from the log alone.
        replayed = self._reread(self.path, self.now).scope_pending(user_id="u1", chat_id="c1")
        self.assertIsNotNone(replayed)
        self.assertEqual(preview.preview_digest, replayed.preview_digest)
        self.assertEqual(self.DOCUMENT, replayed.document)

    def test_a_tampered_document_invalidates_the_preview(self) -> None:
        """原文和它的摘要分两个字段存 —— 手改原文却留着摘要字段,正是要抓的那一下。

        审批的人读的是摘要,真要跑的是原文。两者一旦能分开,授权记录就成了一句转述。
        """
        self._preview()
        self._rewrite_ledger(lambda e: e.get("preview", {}).get("document", {}).__setitem__(
            "allowed_hosts", ["api.nba.com", "cdn.nba.com", "attacker.example.com"]))
        self.assertIsNone(self._reread(self.path, self.now).scope_pending(user_id="u1", chat_id="c1"))

    def test_a_tampered_summary_invalidates_the_preview(self) -> None:
        self._preview()
        self._rewrite_ledger(lambda e: e.get("preview", {}).get("summary", {}).__setitem__("max_fanout", 200))
        self.assertIsNone(self._reread(self.path, self.now).scope_pending(user_id="u1", chat_id="c1"))

    def test_confirmation_must_match_what_was_shown(self) -> None:
        preview = self._preview()
        for bad in ({"intake_id": "I-deadbeef", "options_digest": preview.options_digest},
                    {"intake_id": preview.intake_id, "options_digest": "0" * 64}):
            with self.subTest(bad=bad), self.assertRaises(IntakeStateError):
                self.state.consume_scope_confirmation(
                    user_id="u1", chat_id="c1", message_id="m1", authorization=self._record(), **bad)
        # A refused confirmation must not consume the preview.
        self.assertIsNotNone(self.state.scope_pending(user_id="u1", chat_id="c1"))

    def test_a_confirmed_document_binds_the_record_to_the_document(self) -> None:
        from core.intake_state import canonical_digest

        preview = self._preview()
        record = self._record()
        result = self.state.consume_scope_confirmation(
            user_id="u1", chat_id="c1", message_id="m1", intake_id=preview.intake_id,
            options_digest=preview.options_digest, authorization=record)
        self.assertEqual("confirmed", result["state"])
        self.assertEqual("nba-public-abc", result["authorization_id"])
        self.assertEqual(canonical_digest(record), result["authorization_digest"])
        self.assertEqual(preview.document_digest, result["document_digest"])
        # The slot is empty and a replay returns the same receipt.
        self.assertIsNone(self.state.scope_pending(user_id="u1", chat_id="c1"))
        replay = self.state.consume_scope_confirmation(
            user_id="u1", chat_id="c1", message_id="m1", intake_id=preview.intake_id,
            options_digest=preview.options_digest, authorization=record)
        self.assertEqual(result, replay)

    def test_an_expired_document_preview_cannot_be_confirmed(self) -> None:
        preview = self._preview()
        self.now += 61
        self.assertIsNone(self.state.scope_pending(user_id="u1", chat_id="c1"))
        with self.assertRaises(IntakeStateError):
            self.state.consume_scope_confirmation(
                user_id="u1", chat_id="c1", message_id="m1", intake_id=preview.intake_id,
                options_digest=preview.options_digest, authorization=self._record())

    def test_one_slot_the_two_kinds_cannot_coexist(self) -> None:
        """一个槽只放一样东西 —— 但不能静默把操作员手上那张卡换掉。"""
        self._preview()
        with self.assertRaises(IntakeStateError) as ctx:
            self.state.create_preview(
                target=TARGET, instruction=INSTRUCTION, profile_name=PROFILE, goal_id="g1",
                user_id="u1", chat_id="c1", message_id="m2")
        self.assertEqual("pending_intake_exists", str(ctx.exception))

        # 反过来也一样:先有目标,再贴文档。
        self.state.discard_pending(user_id="u1", chat_id="c1")
        self.state.create_preview(
            target=TARGET, instruction=INSTRUCTION, profile_name=PROFILE, goal_id="g1",
            user_id="u1", chat_id="c1", message_id="m3")
        with self.assertRaises(IntakeStateError) as ctx:
            self._preview()
        self.assertEqual("pending_intake_exists", str(ctx.exception))

    def test_resubmitting_the_same_document_is_idempotent(self) -> None:
        first = self._preview()
        self.assertEqual(first.intake_id, self._preview().intake_id)

    def test_neither_kind_can_be_consumed_through_the_other_door(self) -> None:
        """路走错了要"什么也没发生",不是"拿另一张卡对付过去"。"""
        from core.intake_state import target_card_from_preview

        document_preview = self._preview()
        with self.assertRaises(IntakeStateError):
            self.state.consume_confirmation(
                user_id="u1", chat_id="c1", message_id="m1", intake_id=document_preview.intake_id,
                options_digest=document_preview.options_digest,
                target_card={"schema": "TargetCard/v1"})

        self.state.discard_pending(user_id="u1", chat_id="c1")
        target_preview = self.state.create_preview(
            target=TARGET, instruction=INSTRUCTION, profile_name=PROFILE, goal_id="g1",
            user_id="u1", chat_id="c1", message_id="m4")
        self.assertIsNotNone(target_card_from_preview(target_preview))
        with self.assertRaises(IntakeStateError):
            self.state.consume_scope_confirmation(
                user_id="u1", chat_id="c1", message_id="m4", intake_id=target_preview.intake_id,
                options_digest=target_preview.options_digest, authorization=self._record())
        # 那张目标卡还在原地,没被一次错门调用吃掉。
        self.assertIsNotNone(self.state.pending(user_id="u1", chat_id="c1"))


if __name__ == "__main__":
    unittest.main()
