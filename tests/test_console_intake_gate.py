"""The Console's intake gate: preview → confirm → TargetCard, end to end.

The route used to write a ``ProjectIntakeRequest/v1`` file that nothing read, so
these tests are really about the two things that must not come back: a submit that
no consumer ever picks up, and a confirmation that was bound to something other
than what the operator was shown.
"""
from __future__ import annotations

import json
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
        scope = console_jobs._scope_from_confirmed_card(card, target_id="t-1", run_id="SL-1")

        self.assertEqual("confirmed_target_card:t-1", scope.authorization)
        # No registrable-domain widening: only the host on the card.
        self.assertTrue(scope.check_url("https://target.example.test/login")[0])
        self.assertFalse(scope.check_url("https://api.target.example.test/")[0])
        self.assertFalse(scope.check_url("https://other.example.test/")[0])
        self.assertFalse(scope.check_url("https://forbidden.example.test/")[0])

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


if __name__ == "__main__":
    unittest.main()
