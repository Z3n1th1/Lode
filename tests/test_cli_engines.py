"""CLI engines are text-only inference adapters. They never send HTTP."""
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
sys.path.insert(0, str(_PROJECT_ROOT / "core"))

from core.cli_engines import (  # noqa: E402
    assistant_from_text,
    complete,
    complete_messages,
    configured_engine,
    fallback_to_provider,
    last_error,
    _command,
    _GROK_DISALLOWED_TOOLS,
    _unwrap_cli_output,
)


_ENGINE_ENV = (
    "LODE_HUNTER_ENGINE", "LODE_REASONER_ENGINE", "LODE_EXPLORER_ENGINE",
    "LODE_VERIFIER_ENGINE", "LODE_SPECIALIST_ENGINE",
)


class ConfiguredEngineTests(unittest.TestCase):
    def test_unknown_falls_closed_to_provider(self) -> None:
        cleared = {key: "" for key in _ENGINE_ENV}
        with patch.dict(os.environ, cleared, clear=False):
            self.assertEqual("provider", configured_engine("nope"))
            self.assertEqual("provider", configured_engine(""))

    def test_env_used_when_explicit_is_empty(self) -> None:
        with patch.dict(os.environ, {
            "LODE_REASONER_ENGINE": "codex",
            "LODE_EXPLORER_ENGINE": "pi",
        }, clear=False):
            self.assertEqual("codex", configured_engine("", role="reasoner"))
            self.assertEqual("pi", configured_engine("", role="explorer"))

    def test_explicit_beats_env(self) -> None:
        with patch.dict(os.environ, {"LODE_REASONER_ENGINE": "codex"}, clear=False):
            self.assertEqual("pi", configured_engine("pi", role="reasoner"))

    def test_fallback_flag_is_on_by_default(self) -> None:
        with patch.dict(os.environ, {"LODE_CLI_FALLBACK_PROVIDER": ""}, clear=False):
            os.environ.pop("LODE_CLI_FALLBACK_PROVIDER", None)
            self.assertTrue(fallback_to_provider())
        with patch.dict(os.environ, {"LODE_CLI_FALLBACK_PROVIDER": "0"}, clear=False):
            self.assertFalse(fallback_to_provider())

    def test_explorer_inherits_hunter_when_blank(self) -> None:
        with patch.dict(os.environ, {
            "LODE_HUNTER_ENGINE": "grok",
            "LODE_REASONER_ENGINE": "",
            "LODE_EXPLORER_ENGINE": "",
        }, clear=False):
            os.environ.pop("LODE_REASONER_ENGINE", None)
            os.environ.pop("LODE_EXPLORER_ENGINE", None)
            self.assertEqual("grok", configured_engine("", role="hunter"))
            self.assertEqual("provider", configured_engine("", role="reasoner"))
            self.assertEqual("grok", configured_engine("", role="explorer"))

    def test_verifier_defaults_to_grok(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("LODE_VERIFIER_ENGINE", None)
            os.environ.pop("LODE_SPECIALIST_ENGINE", None)
            self.assertEqual("grok", configured_engine("", role="verifier"))
            self.assertEqual("codex", configured_engine("", role="specialist"))


class GrokBinTests(unittest.TestCase):
    def test_explicit_bin_beats_path_shim(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            exe = Path(tmp) / "grok.exe"
            exe.write_text("x", encoding="utf-8")
            with patch.dict(os.environ, {"LODE_GROK_BIN": str(exe)}, clear=False), \
                    patch("core.cli_engines.shutil.which", return_value=r"D:\nvm\nodejs\grok.CMD"):
                self.assertEqual(str(exe), _command("grok"))

    def test_home_cli_beats_npm_shim(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            exe = home / ".grok" / "bin" / ("grok.exe" if os.name == "nt" else "grok")
            exe.parent.mkdir(parents=True)
            exe.write_text("x", encoding="utf-8")
            with patch.dict(os.environ, {"LODE_GROK_BIN": "", "GROK_BIN": ""}, clear=False), \
                    patch("core.cli_engines.Path.home", return_value=home), \
                    patch("core.cli_engines.shutil.which", return_value=r"D:\nvm\nodejs\grok.CMD"):
                os.environ.pop("LODE_GROK_BIN", None)
                os.environ.pop("GROK_BIN", None)
                self.assertEqual(str(exe), _command("grok"))


class CompleteTests(unittest.TestCase):
    def test_provider_is_not_implemented_here(self) -> None:
        self.assertIsNone(complete("provider", "s", "u"))
        self.assertIn("llm_client", last_error())

    def test_missing_cli_returns_none(self) -> None:
        with patch("core.cli_engines.shutil.which", return_value=None):
            self.assertIsNone(complete("codex", "s", "u"))
            self.assertIn("not found", last_error())

    def test_pi_invokes_print_without_tools(self) -> None:
        seen = {}

        def fake_run(args, *, prompt, timeout, cwd, env=None):
            seen["args"] = list(args)
            seen["prompt"] = prompt
            return "ok"

        with patch("core.cli_engines._command", return_value="pi"), \
             patch("core.cli_engines._run", side_effect=fake_run):
            self.assertEqual("ok", complete("pi", "SYS", "USER"))
        self.assertIn("--print", seen["args"])
        self.assertIn("--no-tools", seen["args"])
        self.assertIn("SYS", seen["prompt"])
        self.assertIn("USER", seen["prompt"])

    def test_grok_clears_the_prompt_file_after_the_call(self) -> None:
        written = {}

        def fake_run(args, *, prompt, timeout, cwd, env=None):
            path = Path(args[args.index("--prompt-file") + 1])
            written["text"] = path.read_text(encoding="utf-8")
            written["path"] = path
            written["args"] = list(args)
            self.assertIn("--no-subagents", args)
            self.assertIn("--verbatim", args)
            self.assertIn("--no-plan", args)
            self.assertNotIn("--permission-mode", args)
            self.assertEqual(
                args[args.index("--disallowed-tools") + 1],
                _GROK_DISALLOWED_TOOLS,
            )
            self.assertIsNone(prompt)
            return "ok"

        with tempfile.TemporaryDirectory() as tmp, \
                patch.dict(os.environ, {"LODE_STATE_DIR": tmp}, clear=False), \
                patch("core.cli_engines._command", return_value="grok"), \
                patch("core.cli_engines._run", side_effect=fake_run):
            self.assertEqual("ok", complete("grok", "SYS", "USER"))
            self.assertIn("SYS", written["text"])
            self.assertEqual("", written["path"].read_text(encoding="utf-8"))
            self.assertIn("search_tool", _GROK_DISALLOWED_TOOLS)
            self.assertIn("use_tool", _GROK_DISALLOWED_TOOLS)

    def test_grok_unwraps_headless_json_envelope(self) -> None:
        def fake_run(args, *, prompt, timeout, cwd, env=None):
            self.assertEqual("json", args[args.index("--output-format") + 1])
            return json.dumps({"text": '{"ok": true}', "stopReason": "end_turn"})

        with tempfile.TemporaryDirectory() as tmp, \
                patch.dict(os.environ, {"LODE_STATE_DIR": tmp}, clear=False), \
                patch("core.cli_engines._command", return_value="grok"), \
                patch("core.cli_engines._run", side_effect=fake_run):
            self.assertEqual('{"ok": true}', complete("grok", "SYS", "USER"))

    def test_unwrap_leaves_lode_tool_calls_alone(self) -> None:
        blob = '{"tool_calls":[{"id":"c1","function":{"name":"submit_verdict","arguments":"{}"}}]}'
        self.assertEqual(blob, _unwrap_cli_output(blob))

    def test_grok_passes_json_schema(self) -> None:
        seen = {}

        def fake_run(args, *, prompt, timeout, cwd, env=None):
            seen["schema"] = args[args.index("--json-schema") + 1]
            return json.dumps({"text": '{"analysis":"x","conclusion":"dead_end"}', "stopReason": "end_turn"})

        with tempfile.TemporaryDirectory() as tmp, \
                patch.dict(os.environ, {"LODE_STATE_DIR": tmp}, clear=False), \
                patch("core.cli_engines._command", return_value="grok"), \
                patch("core.cli_engines._run", side_effect=fake_run):
            text = complete(
                "grok", "SYS", "USER",
                json_schema={"type": "object", "required": ["analysis"]},
            )
        self.assertIn("analysis", seen["schema"])
        self.assertEqual('{"analysis":"x","conclusion":"dead_end"}', text)

    def test_complete_messages_parses_lode_tool_calls_and_keeps_native_tools_off(self) -> None:
        seen = {}

        def fake_run(args, *, prompt, timeout, cwd, env=None):
            seen["args"] = list(args)
            seen["prompt"] = prompt
            return '{"tool_calls":[{"id":"c1","function":{"name":"fetch_url","arguments":"{\\"url\\":\\"https://x/\\"}"}}]}'

        with patch("core.cli_engines._command", return_value="pi"), \
             patch("core.cli_engines._run", side_effect=fake_run):
            message = complete_messages(
                "pi",
                [{"role": "user", "content": "look"}],
                tools=[{"type": "function", "function": {"name": "fetch_url", "description": "get"}}],
            )
        self.assertIn("--no-tools", seen["args"])
        self.assertIn("fetch_url", seen["prompt"])
        self.assertEqual("fetch_url", message["tool_calls"][0]["function"]["name"])

    def test_assistant_from_text_without_calls_is_plain_content(self) -> None:
        message = assistant_from_text("just a sentence")
        self.assertEqual("just a sentence", message["content"])
        self.assertEqual([], message["tool_calls"])


if __name__ == "__main__":
    unittest.main()
