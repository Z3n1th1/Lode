"""One-shot, tool-disabled reasoning through installed agent CLIs.

These adapters deliberately use the CLIs only as text inference backends. They
do not hand a live SRC target to a CLI tool loop: Lode remains the sole owner of
scope admission, HTTP execution, request budgets, rate limits and audit logs.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import threading
import uuid
from pathlib import Path
import json
import re
from typing import Any, Dict, List, Mapping, Optional, Sequence

ENGINES = ("provider", "pi", "grok", "codex", "claude")
ENGINE_ENV: Dict[str, str] = {
    "hunter": "LODE_HUNTER_ENGINE",
    "reasoner": "LODE_REASONER_ENGINE",
    "explorer": "LODE_EXPLORER_ENGINE",
    "verifier": "LODE_VERIFIER_ENGINE",
    "specialist": "LODE_SPECIALIST_ENGINE",
}
ROLE_DEFAULTS: Dict[str, str] = {
    "hunter": "provider",
    "reasoner": "provider",
    "explorer": "",
    "verifier": "grok",
    "specialist": "codex",
}
MAX_OUTPUT_CHARS = 512_000
_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*\n?(.*?)\n?\s*```", re.S)

_ERROR = threading.local()


def _set_error(value: str) -> None:
    _ERROR.value = str(value or "")[:500]


def last_error() -> str:
    return str(getattr(_ERROR, "value", "") or "")


def configured_engine(explicit: str = "", *, role: str = "reasoner") -> str:
    """Resolve an engine for ``role``.

    Muteki split: Planner (``reasoner``) stays on the cheap HTTP provider;
    Worker (``explorer``) follows the operator's 主力 (``hunter``) when blank.
    Switching Grok vs ChatGPT is one Worker field. Verifier/specialist have
    their own defaults and do not silently follow the hunter.
    """
    value = str(explicit or "").strip().lower()
    if value in {"", "inherit", "hunter"} and role in {"reasoner", "explorer"}:
        value = ""
    if not value:
        value = os.environ.get(ENGINE_ENV.get(role, ""), "").strip().lower()
    if not value and role in {"explorer", "hunter"}:
        value = os.environ.get(ENGINE_ENV["hunter"], "").strip().lower()
    if not value and role == "hunter":
        value = os.environ.get(ENGINE_ENV["reasoner"], "").strip().lower()
    if not value:
        value = ROLE_DEFAULTS.get(role, "") or "provider"
    return value if value in ENGINES else "provider"


def fallback_to_provider() -> bool:
    """Missing/unlogged/timed-out CLIs fall back to the HTTP provider.

    Default is on so a hunt does not stop because Pi/Grok/Codex is not installed.
    Set ``LODE_CLI_FALLBACK_PROVIDER=0`` to keep the old fail-closed behaviour.
    """
    raw = os.environ.get("LODE_CLI_FALLBACK_PROVIDER", "1").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def _prompt(system: str, user: str) -> str:
    return f"SYSTEM INSTRUCTIONS:\n{system}\n\nUSER TASK:\n{user}"


def _grok_home_cli() -> Optional[str]:
    """The Grok *subscription* CLI, not the npm ``@xai-official/grok`` shim."""
    path = Path.home() / ".grok" / "bin" / ("grok.exe" if os.name == "nt" else "grok")
    return str(path) if path.is_file() else None


def _command(name: str) -> Optional[str]:
    # On Windows, npm global shims are .cmd files. shutil.which(name) normally
    # finds them; the explicit suffix keeps tests and unusual PATHEXT setups sane.
    # ``grok`` is special: PATH often has Node's grok.CMD first, which does not
    # accept ``--prompt-file`` / ``--no-subagents`` and makes every explore
    # return explorer_llm_unavailable.
    if name == "grok":
        for candidate in (
            os.environ.get("LODE_GROK_BIN", "").strip(),
            os.environ.get("GROK_BIN", "").strip(),
            _grok_home_cli() or "",
        ):
            if candidate and Path(candidate).is_file():
                return candidate
    return shutil.which(name) or shutil.which(name + ".cmd")


def _run(args: Sequence[str], *, prompt: Optional[str], timeout: float, cwd: Path,
         env: Optional[Dict[str, str]] = None) -> Optional[str]:
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    try:
        result = subprocess.run(
            list(args), input=prompt, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=max(5.0, float(timeout)),
            cwd=str(cwd), env=env, creationflags=flags, check=False,
        )
    except subprocess.TimeoutExpired:
        _set_error(f"timeout after {timeout}s")
        return None
    except OSError as exc:
        _set_error(f"{type(exc).__name__}: {str(exc)[:300]}")
        return None
    text = str(result.stdout or "").strip()
    if result.returncode != 0:
        detail = str(result.stderr or text or f"exit {result.returncode}").strip()
        _set_error(f"exit {result.returncode}: {detail[:400]}")
        # Headless grok often prints the answer then exits 1 on max_turns/cancel.
        if not text:
            return None
    if not text:
        _set_error("empty output")
        return None
    if result.returncode == 0:
        _set_error("")
    return text[:MAX_OUTPUT_CHARS]


def _state_dir() -> Path:
    raw = os.environ.get("LODE_STATE_DIR", "").strip()
    return Path(raw) if raw else Path(__file__).resolve().parents[1] / "lode-state"


# Native Grok Build tools. ``--tools ""`` is ignored (stock profile still
# injects shell/web), so Explorer spent turn 1 on run_terminal_command and
# ``--max-turns 1`` cancelled before any JSON reached stdout.
_GROK_DISALLOWED_TOOLS = ",".join((
    "run_terminal_cmd", "run_terminal_command",
    "web_search", "web_fetch",
    "search_replace", "read_file", "write", "grep", "list_dir",
    "Agent", "enter_plan_mode", "exit_plan_mode",
    "spawn_subagent", "monitor", "todo_write",
    "search_tool", "use_tool", "ask_user_question",
))


def _unwrap_cli_output(text: str) -> str:
    """Grok ``--output-format json`` wraps the model text in ``{"text": ...}``."""
    raw = str(text or "").strip()
    if not raw.startswith("{"):
        return raw
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return raw
    if isinstance(data, dict) and "text" in data and "stopReason" in data:
        inner = str(data.get("text") or "").strip()
        return inner or raw
    return raw


def _grok(engine_path: str, prompt: str, timeout: float, cwd: Path,
          json_schema: Optional[Dict[str, Any]] = None) -> Optional[str]:
    # Grok headless intentionally does not read a prompt from stdin. Use a
    # short-lived file under the git-ignored state directory, then overwrite
    # it with an empty file. The path remains for audit; prompt contents do not.
    # ``--permission-mode plan`` selects the grok-build-plan agent and waits
    # for approval; Lode needs a one-shot text completion, so ``--no-plan``.
    prompt_dir = _state_dir() / "cli-prompts"
    prompt_dir.mkdir(parents=True, exist_ok=True)
    prompt_path = prompt_dir / f"grok-{os.getpid()}-{uuid.uuid4().hex}.txt"
    prompt_path.write_text(prompt, encoding="utf-8")
    try:
        args = [
            engine_path, "--prompt-file", str(prompt_path),
            "--output-format", "json", "--no-subagents", "--no-plan",
            "--disable-web-search", "--max-turns", "1",
            "--disallowed-tools", _GROK_DISALLOWED_TOOLS,
            "--verbatim",
        ]
        if json_schema:
            args.extend(["--json-schema", json.dumps(json_schema, ensure_ascii=False)])
        raw = _run(args, prompt=None, timeout=timeout, cwd=cwd)
        return None if raw is None else _unwrap_cli_output(raw)
    finally:
        try:
            prompt_path.write_text("", encoding="utf-8")
        except OSError:
            pass


def complete(engine: str, system: str, user: str, *, timeout: float = 90.0,
             cwd: Optional[str | Path] = None,
             json_schema: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """Return one text completion from ``engine``, or ``None`` plus error.

    ``provider`` is intentionally not implemented here; callers retain their
    existing in-process provider pool for that engine.
    """
    selected = configured_engine(engine)
    if selected == "provider":
        _set_error("provider engine belongs to core.llm_client")
        return None
    executable = _command(selected)
    if not executable:
        _set_error(f"{selected} CLI not found on PATH")
        return None
    if cwd:
        workdir = Path(cwd)
    elif selected == "grok":
        # cli-work sits inside the Lode git repo. Grok then loads AGENTS.md and
        # acts as a coding agent (search_tool, run_terminal_command) instead of
        # a text completion. Keep grok's cwd outside the repo.
        override = os.environ.get("LODE_GROK_CWD", "").strip()
        workdir = Path(override) if override else Path(
            os.environ.get("TEMP") or os.environ.get("TMP") or "/tmp"
        ) / "lode-grok-cli"
    else:
        workdir = _state_dir() / "cli-work"
    workdir.mkdir(parents=True, exist_ok=True)
    message = _prompt(system, user)

    if selected == "pi":
        return _run([
            executable, "--print", "--mode", "text", "--no-tools",
            "--no-session", "--no-extensions", "--no-skills",
            "--no-context-files",
        ], prompt=message, timeout=timeout, cwd=workdir)
    if selected == "claude":
        return _run([
            executable, "--print", "--input-format", "text",
            "--output-format", "text", "--tools", "",
            "--permission-prompts", "none", "--no-session-persistence",
            "--restricted", "--bare",
        ], prompt=message, timeout=timeout, cwd=workdir)
    if selected == "codex":
        return _run([
            executable, "exec", "--sandbox", "read-only", "--ephemeral",
            "--ignore-rules", "--skip-git-repo-check", "--color", "never",
            "-C", str(workdir), "-",
        ], prompt=message, timeout=timeout, cwd=workdir)
    if selected == "grok":
        return _grok(executable, message, timeout, workdir, json_schema=json_schema)
    _set_error(f"unsupported engine: {selected}")
    return None


_TOOLS_PREAMBLE = """\
You may use ONLY the Lode-controlled tools listed below. You have no bash, no
edit, no write, no local filesystem, and no network of your own. HTTP, scope
admission, rate limits and audit stay in Lode.

To call a tool, output JSON only (no markdown fence):
{{"tool_calls":[{{"id":"c1","function":{{"name":"TOOL_NAME","arguments":"{{}}"}}}}]}}

`arguments` is a JSON string. To finish without a tool, output your analysis as
JSON or plain text.

TOOLS:
{tools}
"""


def _transcript(messages: Sequence[Mapping[str, Any]]) -> tuple[str, str]:
    system_parts: List[str] = []
    body: List[str] = []
    for message in messages or ():
        role = str(message.get("role") or "")
        content = str(message.get("content") or "")
        if role == "system":
            if content:
                system_parts.append(content)
            continue
        if role == "assistant":
            calls = message.get("tool_calls") or []
            if calls:
                body.append("ASSISTANT TOOL CALLS:\n" + json.dumps(calls, ensure_ascii=False))
            if content:
                body.append("ASSISTANT:\n" + content)
            continue
        if role == "tool":
            body.append(f"TOOL RESULT ({message.get('tool_call_id') or ''}):\n{content}")
            continue
        body.append("USER:\n" + content)
    return "\n\n".join(system_parts), "\n\n".join(body)


def _tools_block(tools: Any) -> str:
    names: List[str] = []
    for item in tools or ():
        if not isinstance(item, Mapping):
            continue
        function = item.get("function") if isinstance(item.get("function"), Mapping) else item
        name = str(function.get("name") or "").strip()
        if not name:
            continue
        description = str(function.get("description") or "").strip()
        names.append(f"- {name}: {description}" if description else f"- {name}")
    return "\n".join(names) if names else "(none)"


def _extract_json_object(text: str) -> Optional[Dict[str, Any]]:
    raw = str(text or "").strip()
    if not raw:
        return None
    blobs = [raw]
    fenced = _JSON_FENCE_RE.search(raw)
    if fenced:
        blobs.append(fenced.group(1).strip())
    start = raw.find("{")
    end = raw.rfind("}")
    if 0 <= start < end:
        blobs.append(raw[start:end + 1])
    for blob in blobs:
        try:
            parsed = json.loads(blob)
        except (ValueError, TypeError):
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def assistant_from_text(text: str) -> Dict[str, Any]:
    """Turn a CLI completion into an OpenAI-style assistant message."""
    parsed = _extract_json_object(text)
    calls_raw = (parsed or {}).get("tool_calls") if parsed else None
    if isinstance(calls_raw, list) and calls_raw:
        calls: List[Dict[str, Any]] = []
        for index, call in enumerate(calls_raw):
            if not isinstance(call, Mapping):
                continue
            function = call.get("function") if isinstance(call.get("function"), Mapping) else call
            name = str(function.get("name") or call.get("name") or "").strip()
            if not name:
                continue
            arguments = function.get("arguments")
            if arguments is None:
                arguments = call.get("arguments")
            if not isinstance(arguments, str):
                arguments = json.dumps(arguments or {}, ensure_ascii=False)
            calls.append({
                "id": str(call.get("id") or f"c{index}"),
                "type": "function",
                "function": {"name": name, "arguments": arguments},
            })
        if calls:
            return {
                "role": "assistant",
                "content": str((parsed or {}).get("content") or ""),
                "tool_calls": calls,
            }
    return {"role": "assistant", "content": str(text or ""), "tool_calls": []}


def complete_messages(
    engine: str,
    messages: Sequence[Mapping[str, Any]],
    *,
    tools: Any = None,
    timeout: float = 90.0,
    cwd: Optional[str | Path] = None,
) -> Optional[Dict[str, Any]]:
    """One CLI completion that can carry Lode tool_calls. Native CLI tools stay off."""
    system, user = _transcript(messages)
    if tools:
        system = (_TOOLS_PREAMBLE.format(tools=_tools_block(tools))
                  + ("\n\n" + system if system else ""))
    text = complete(engine, system or "Follow the user task.", user or "",
                    timeout=timeout, cwd=cwd)
    if not text:
        return None
    return assistant_from_text(text)


__all__ = ["ENGINES", "ENGINE_ENV", "ROLE_DEFAULTS", "configured_engine",
           "fallback_to_provider", "complete", "complete_messages",
           "assistant_from_text", "last_error"]
