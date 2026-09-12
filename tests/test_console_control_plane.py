"""Regression tests for the local, read-only ControlPlane Console."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient


PENTEST_AGENT = Path(__file__).resolve().parents[1]
if str(PENTEST_AGENT) not in sys.path:
    sys.path.insert(0, str(PENTEST_AGENT))


SECRET_SENTINEL = "LODE_SECRET_SENTINEL"


def write_jsonl(path: Path, events: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(event, ensure_ascii=False) + "\n" for event in events),
        encoding="utf-8",
    )


class ReadOnlyControlPlaneTests(unittest.TestCase):
    def test_intel_projects_latest_radar_run_into_console_rows(self) -> None:
        from console.control_plane import ReadOnlyControlPlane

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "state"
            run = state / "intel" / "runs" / "demo-run"
            run.mkdir(parents=True)
            (run / "candidates.jsonl").write_text(json.dumps({
                "kind": "article", "source": "demo-ai", "title": "AI update",
                "summary": "public summary", "value": "https://example.com/a",
                "score": 60, "tags": ["ai", "developer"],
            }) + "\n", encoding="utf-8")
            rows = ReadOnlyControlPlane(state).intel()
            self.assertEqual(1, len(rows))
            self.assertEqual("demo-ai", rows[0]["source"])
            self.assertEqual("public summary", rows[0]["summary"])
            self.assertEqual("article", rows[0]["kind"])

    def test_intake_toggle_sanitizer_hard_disables_bruteforce(self) -> None:
        from console.control_plane import _sanitize_toggles

        sanitized = _sanitize_toggles({
            "scan_enabled": True,
            "brute": {
                "enabled": True,
                "path": True,
                "password": True,
                "max_attempts": 100000,
                "rate_limit_per_min": 6000,
            },
        })
        self.assertTrue(sanitized["scan_enabled"])
        self.assertEqual(0, sanitized["brute"]["max_attempts"])
        self.assertEqual(0, sanitized["brute"]["rate_limit_per_min"])
        self.assertFalse(any(sanitized["brute"].get(key) for key in (
            "enabled", "path", "port", "password", "username", "sms", "subdomain"
        )))

    def test_public_target_rejects_embedded_credentials_and_bad_ports(self) -> None:
        from console.control_plane import _valid_public_target

        self.assertEqual("", _valid_public_target("https://user:secret@example.com"))
        self.assertEqual("", _valid_public_target("https://example.com:bad"))
        self.assertEqual("https://example.com:8443/path", _valid_public_target("https://example.com:8443/path"))

    def _write_state(self, root: Path, *, create_lock_sidecars: bool = True) -> None:
        write_jsonl(
            root / "goals.jsonl",
            [
                {
                    "event": "created",
                    "goal": {
                        "goal_id": "G-001",
                        "target": "https://example.test",
                        "profile_name": "standard-pentest",
                        "instruction": f"do not reveal {SECRET_SENTINEL}",
                        "created_at": 1_000.0,
                        "endpoints_total": 3,
                        "timebox_seconds": 7_200,
                    },
                },
                {"event": "endpoint_audited", "goal_id": "G-001", "endpoint": "GET /health"},
                {
                    "event": "finding_recorded",
                    "goal_id": "G-001",
                    "finding": {"type": "rce", "verified": True, "detail": SECRET_SENTINEL},
                },
            ],
        )
        with (root / "goals.jsonl").open("a", encoding="utf-8") as handle:
            handle.write("{not-json}\n")

        write_jsonl(
            root / "pending_profiles.jsonl",
            [
                {
                    "event": "created",
                    "pending": {
                        "user_id": "operator-should-not-leak",
                        "chat_id": "chat-should-not-leak",
                        "message_id": "message-should-not-leak",
                        "target": "https://pending.example.test",
                        "instruction": SECRET_SENTINEL,
                        "profile_ids": ["standard-pentest", "ctf-fast-score"],
                        "goal_id": "G-002",
                        "created_at": 1_020.0,
                        "expires_at": 1_920.0,
                    },
                }
            ],
        )
        write_jsonl(
            root / "strix_tasks.jsonl",
            [
                {
                    "event": "created",
                    "id": "T-001",
                    "goal_id": "G-001",
                    "profile_name": "standard-pentest",
                    "target": "https://example.test",
                    "instruction": SECRET_SENTINEL,
                    "user_id": "operator-should-not-leak",
                    "chat_id": "chat-should-not-leak",
                    "output_path": f"C:/private/{SECRET_SENTINEL}",
                    "run_id": "run-001",
                    "status": "running",
                    "created_ts": 1_030.0,
                },
                {
                    "event": "blocked",
                    "id": "T-001",
                    "status": "blocked",
                    "blocked_reason": "external_tool_runner_unconfigured",
                    "finished_ts": 1_040.0,
                    "error": SECRET_SENTINEL,
                },
            ],
        )
        write_jsonl(
            root / "target_intakes.jsonl",
            [
                {
                    "event": "preview_created",
                    "preview": {
                        "intake_id": "I-001",
                        "user_id": "operator-should-not-leak",
                        "chat_id": "chat-should-not-leak",
                        "message_id": "message-should-not-leak",
                        "target": "https://intake.example.test",
                        "canonical_host": "intake.example.test",
                        "entrypoint": "https://intake.example.test/",
                        "instruction": SECRET_SENTINEL,
                        "instruction_digest": "a" * 64,
                        "profile_name": "standard-pentest",
                        "goal_id": "G-INTAKE-001",
                        "created_at": 1_050.0,
                        "expires_at": 1_950.0,
                        "scope_digest": "b" * 64,
                        "options_digest": "c" * 64,
                        "preview_digest": "d" * 64,
                        "options": {
                            "asset_inventory": {"enabled": False, "mode": "not_requested"},
                            "fingerprint": {"enabled": False, "mode": "not_requested"},
                            "arl_next": {"enabled": False, "mode": "not_available"},
                            "intelligence": {"enabled": False, "mode": "metadata_only"},
                            "poc_research": {"enabled": False, "mode": "metadata_only"},
                            "proxy_route": {"enabled": False, "profile": ""},
                        },
                    },
                }
            ],
        )
        card_path = root / "strix_tasks" / "T-001" / "quarantine" / "run-001" / "sandbox-run.json"
        card_path.parent.mkdir(parents=True)
        card_path.write_text(
            json.dumps(
                {
                    "schema": "SandboxRunCard/v1",
                    "status": "blocked",
                    "execution_mode": "synthetic",
                    "network": "none",
                    "rootless": False,
                    "source_path": SECRET_SENTINEL,
                }
            ),
            encoding="utf-8",
        )
        if create_lock_sidecars:
            for source_name in ("goals.jsonl", "pending_profiles.jsonl", "strix_tasks.jsonl", "target_intakes.jsonl"):
                (root / f"{source_name}.lock").write_bytes(b"\0")

    def test_snapshot_refuses_sources_without_existing_lock_sidecars(self) -> None:
        from console.control_plane import ReadOnlyControlPlane

        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)
            self._write_state(state_dir, create_lock_sidecars=False)
            before = {
                relative: (state_dir / relative).read_bytes()
                for relative in ("goals.jsonl", "pending_profiles.jsonl", "strix_tasks.jsonl", "target_intakes.jsonl")
            }

            snapshot = ReadOnlyControlPlane(state_dir, now_fn=lambda: 1_100.0).snapshot()

            for source_name in ("goals.jsonl", "pending_profiles.jsonl", "strix_tasks.jsonl", "target_intakes.jsonl"):
                self.assertFalse((state_dir / f"{source_name}.lock").exists())
            self.assertEqual("unavailable", snapshot["state_dir_status"])
            self.assertEqual([], snapshot["goals"])
            self.assertEqual([], snapshot["tasks"])
            self.assertEqual([], snapshot["pending_profiles"])
            self.assertEqual([], snapshot["pending_intakes"])
            for relative, content in before.items():
                self.assertEqual(content, (state_dir / relative).read_bytes())

    def test_snapshot_is_redacted_bounded_and_does_not_change_state_files(self) -> None:
        from console.control_plane import ReadOnlyControlPlane

        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)
            self._write_state(state_dir)
            before = {
                relative: (state_dir / relative).read_bytes()
                for relative in ("goals.jsonl", "pending_profiles.jsonl", "strix_tasks.jsonl", "target_intakes.jsonl")
            }

            snapshot = ReadOnlyControlPlane(state_dir, now_fn=lambda: 1_100.0).snapshot()

            self.assertEqual("ControlPlaneDashboard/v1", snapshot["schema"])
            self.assertEqual("partial", snapshot["state_dir_status"])
            self.assertEqual("rce_confirmed", snapshot["goals"][0]["stop_condition"])
            self.assertEqual(1, snapshot["goals"][0]["audited_endpoint_count"])
            self.assertEqual("blocked", snapshot["tasks"][0]["status"])
            self.assertEqual(
                "external_tool_runner_unconfigured",
                snapshot["tasks"][0]["blocked_reason"],
            )
            self.assertEqual(["standard-pentest", "ctf-fast-score"], snapshot["pending_profiles"][0]["profiles"])
            self.assertEqual("I-001", snapshot["pending_intakes"][0]["intake_id"])
            self.assertEqual("https://intake.example.test", snapshot["pending_intakes"][0]["target"])
            self.assertFalse(snapshot["pending_intakes"][0]["asset_inventory_enabled"])
            self.assertEqual("synthetic", snapshot["sandbox_runs"][0]["execution_mode"])
            self.assertEqual("preview_only", snapshot["capabilities"]["target_intake"])
            serialized = json.dumps(snapshot, ensure_ascii=False, sort_keys=True)
            self.assertNotIn(SECRET_SENTINEL, serialized)
            self.assertNotIn("operator-should-not-leak", serialized)
            self.assertNotIn("chat-should-not-leak", serialized)
            self.assertNotIn("output_path", serialized)
            for relative, content in before.items():
                self.assertEqual(content, (state_dir / relative).read_bytes())

    def test_dashboard_requires_a_login_session(self) -> None:
        from console.control_plane import create_app

        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "state"
            static_dir = Path(tmp) / "static"
            static_dir.mkdir(parents=True)
            (static_dir / "index.html").write_text("<main>control-plane</main>", encoding="utf-8")
            assets_dir = static_dir / "assets"
            assets_dir.mkdir()
            (assets_dir / "main.js").write_text("export {}", encoding="utf-8")
            self._write_state(state_dir)
            app = create_app(
                state_dir=state_dir,
                password="strong-local-password",
                session_secret="session-secret-for-test-0123456789",
                static_dir=static_dir,
            )

            with TestClient(app) as client:
                self.assertEqual(401, client.get("/api/v1/dashboard").status_code)
                self.assertEqual(401, client.post("/api/v1/session", json={"password": "wrong"}).status_code)
                login = client.post("/api/v1/session", json={"password": "strong-local-password"})
                self.assertEqual(204, login.status_code)
                dashboard = client.get("/api/v1/dashboard")
                self.assertEqual(200, dashboard.status_code)
                self.assertEqual("ControlPlaneDashboard/v1", dashboard.json()["schema"])
                self.assertEqual("no-store", dashboard.headers["cache-control"])
                self.assertEqual(200, client.get("/").status_code)
                asset = client.get("/assets/main.js")
                self.assertEqual(200, asset.status_code)
                self.assertTrue(asset.headers["content-type"].startswith("text/javascript"))
                self.assertEqual(204, client.delete("/api/v1/session").status_code)
                self.assertEqual(401, client.get("/api/v1/dashboard").status_code)

    def test_src_autopilot_projection_is_authenticated_bounded_and_local_only(self) -> None:
        from core.src_blackboard import SrcBlackboard
        from console.control_plane import create_app

        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "state"
            board = SrcBlackboard(state_dir / "src-blackboard.json")
            board.sync_candidates([{
                "candidate_id": "SC-LOCAL", "url": "https://example.test/admin/export?token=[redacted]",
                "priority": 90, "sources": ["openapi"], "next_phase": "C-human-gated-verification",
            }], run_id="SA-local")
            app = create_app(
                state_dir=state_dir,
                password="strong-local-password",
                session_secret="session-secret-for-test-0123456789",
            )
            with TestClient(app) as client:
                self.assertEqual(401, client.get("/api/v1/src-autopilot").status_code)
                client.post("/api/v1/session", json={"password": "strong-local-password"})
                response = client.get("/api/v1/src-autopilot")
                self.assertEqual(200, response.status_code)
                body = response.json()
                self.assertEqual("SrcAutopilotView/v1", body["schema"])
                self.assertTrue(body["available"])
                self.assertEqual("/admin/export", body["candidates"][0]["path"])
                self.assertNotIn("result_ref", json.dumps(body))
                self.assertNotIn("token=value", json.dumps(body))
                dashboard = client.get("/api/v1/dashboard").json()
                self.assertTrue(dashboard["src_autopilot"]["available"])

    def test_login_supports_a_unicode_password(self) -> None:
        from console.control_plane import create_app

        with tempfile.TemporaryDirectory() as tmp:
            password = "本地控制面-强口令-2026-安全测试"
            app = create_app(
                state_dir=Path(tmp) / "state",
                password=password,
                session_secret="session-secret-for-test-0123456789",
            )

            with TestClient(app) as client:
                self.assertEqual(204, client.post("/api/v1/session", json={"password": password}).status_code)

    def test_app_rejects_short_authentication_secrets(self) -> None:
        from console.control_plane import create_app

        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "state"
            with self.assertRaisesRegex(ValueError, "^console_password_too_short$"):
                create_app(
                    state_dir=state_dir,
                    password="short-password",
                    session_secret="session-secret-for-test-0123456789",
                )
            with self.assertRaisesRegex(ValueError, "^console_session_secret_too_short$"):
                create_app(
                    state_dir=state_dir,
                    password="strong-local-password",
                    session_secret="too-short",
                )

    def test_model_active_switch_endpoint(self) -> None:
        """R2: POST /api/v1/model/active 只接受池内 provider,原子写状态文件,GET /api/v1/models 回显。"""
        from console.control_plane import create_app

        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "state"
            state_dir.mkdir(parents=True)
            (state_dir / "model_pool_status.json").write_text(
                json.dumps(
                    {
                        "checked_at": 1_100.0,
                        "total": 2,
                        "up": 1,
                        "providers": [
                            {"name": "p-one", "model": "m-one", "host": "a.test", "up": True},
                            {"name": "p-two", "model": "m-two", "host": "b.test", "up": False},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            app = create_app(
                state_dir=state_dir,
                password="strong-local-password",
                session_secret="session-secret-for-test-0123456789",
            )

            with TestClient(app) as client:
                self.assertEqual(401, client.post("/api/v1/model/active", json={"name": "p-two"}).status_code)
                self.assertEqual(204, client.post("/api/v1/session", json={"password": "strong-local-password"}).status_code)
                bad = client.post("/api/v1/model/active", json={"name": "ghost"})
                self.assertEqual(400, bad.status_code)
                self.assertEqual("unknown_provider", bad.json()["detail"])
                self.assertFalse((state_dir / "model_active_provider.json").exists())
                ok = client.post("/api/v1/model/active", json={"name": "p-two"})
                self.assertEqual(200, ok.status_code)
                self.assertEqual({"ok": True, "active": "p-two", "model": "m-two", "up": False}, ok.json())
                doc = json.loads((state_dir / "model_active_provider.json").read_text(encoding="utf-8"))
                self.assertEqual("p-two", doc["name"])
                self.assertEqual("m-two", doc["model"])
                listing = client.get("/api/v1/models").json()
                self.assertEqual("p-two", listing["active"])
                self.assertEqual("m-two", listing["active_model"])
                self.assertEqual(2, len(listing["providers"]))
    def test_dsh_reverse_proxy_strips_prefix_and_rewrites_absolute_refs(self) -> None:
        """/dsh/ 反代:剥前缀转发、HTML/JS/CSS 绝对路径重写、Location 重写、会话鉴权。"""
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        from console.control_plane import create_app

        class FakeDsh(BaseHTTPRequestHandler):
            def log_message(self, *args: object) -> None:
                pass

            def _handle(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                if self.path == "/":
                    payload = (
                        b'<html><script type="module" crossorigin src="/assets/index.js"></script>'
                        b'<script>window.__DSH_BOOT__={"entries":[{"url":"/plugins/x/client.js"}]}</script>'
                        b'<link rel="manifest" href="/manifest.webmanifest" /></html>'
                    )
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                elif self.path == "/assets/app.js":
                    payload = b'fetch("/api/respond"); import(`/plugins/y/client.js`); const c = "/compact";'
                    self.send_response(200)
                    self.send_header("Content-Type", "text/javascript")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                elif self.path == "/go":
                    self.send_response(302)
                    self.send_header("Location", "/home")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                else:
                    payload = json.dumps(
                        {"method": self.command, "path": self.path, "body": body.decode("utf-8", "replace")}
                    ).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)

            do_GET = _handle
            do_POST = _handle

        upstream = ThreadingHTTPServer(("127.0.0.1", 0), FakeDsh)
        thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                app = create_app(
                    state_dir=Path(tmp) / "state",
                    password="strong-local-password",
                    session_secret="session-secret-for-test-0123456789",
                    dsh_upstream=f"http://127.0.0.1:{upstream.server_port}",
                )
                with TestClient(app) as client:
                    self.assertEqual(401, client.get("/dsh/").status_code)
                    client.post("/api/v1/session", json={"password": "strong-local-password"})

                    html = client.get("/dsh/")
                    self.assertEqual(200, html.status_code)
                    self.assertIn('src="/dsh/assets/index.js"', html.text)
                    self.assertIn('"url":"/dsh/plugins/x/client.js"', html.text)
                    self.assertIn('href="/dsh/manifest.webmanifest"', html.text)

                    js = client.get("/dsh/assets/app.js")
                    self.assertIn('fetch("/dsh/api/respond")', js.text)
                    self.assertIn("import(`/dsh/plugins/y/client.js`)", js.text)
                    # 聊天斜杠命令等非 URL 字面量不得被重写
                    self.assertIn('"/compact"', js.text)

                    echo = client.post("/dsh/api/chat?q=1", content=b'{"hi":1}')
                    self.assertEqual(200, echo.status_code)
                    doc = echo.json()
                    self.assertEqual("POST", doc["method"])
                    self.assertEqual("/api/chat?q=1", doc["path"])
                    self.assertEqual('{"hi":1}', doc["body"])

                    redirect = client.get("/dsh/go", follow_redirects=False)
                    self.assertEqual(302, redirect.status_code)
                    self.assertEqual("/dsh/home", redirect.headers["location"])
        finally:
            upstream.shutdown()
            upstream.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
