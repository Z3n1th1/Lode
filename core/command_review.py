"""Regex-first command judgment. Record always. Hit → intercept, never call AI.

This is the first gate in front of Bash / PowerShell / cmd. It exists so a
delete or a dump cannot wait on a model. Query and INSERT-shaped test data
are not this gate's job — those stay allowed.

Match order is the point: each rule is tried against the **complete** command
string, first hit wins, and a hit never calls an LLM.
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple

# Tools that mean "the agent is about to run a local command".
SHELL_TOOLS = frozenset({
    "run_terminal_cmd", "run_terminal_command", "bash", "shell", "powershell",
    "pwsh", "cmd", "terminal", "execute_command", "exec_command", "run_command",
    "local_shell", "spawn",
})
_COMMAND_KEYS = (
    "command", "cmd", "script", "input", "code", "command_line", "argv",
    "arguments", "line",
)

# Ordered. First match on the complete command intercepts.
# CRUD: query/INSERT pass; UPDATE / DELETE / DROP / TRUNCATE / dump / rm do not.
_DENY_RULES: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    ("dump", re.compile(
        r"(?is)(?:\b(?:mysql|pg|mongo|redis|ora)dump\b"
        r"|\binto\s+(?:out|dump)file\b"
        r"|\bload_file\s*\("
        r"|\b(?:--dump|--dump-all|-dump)\b"
        r"|\bselect\s+.+\s+into\s+(?:out|dump)file\b)"
    )),
    ("destructive_fs", re.compile(
        r"(?is)(?:\bremove-item\b|\bclear-item\b|\bclear-content\b"
        r"|\brm\s+-r[f]?\b|\brm\s+-fr\b|\brm\s+-rf\b"
        r"|\brmdir\b|\bunlink\b|\bshred\b|\bwipe\b"
        r"|\berase\b|\bdel\s+/[fq]"
        r"|\brd\s+/s)"
    )),
    ("destructive_sql", re.compile(
        r"(?is)(?:\bdrop\s+(?:table|database|index|view|schema|user|procedure)\b"
        r"|\btruncate\s+(?:table\b|\w+)"
        r"|\bdelete\s+from\b)"
    )),
    ("mutating_update", re.compile(
        r"(?is)\bupdate\s+\S+\s+set\b"
    )),
    # Catch-all the operator asked for. Last on purpose: earlier rules name the
    # real reason; this one still stops a bare `del` / `rm` / `update`.
    ("destructive_word", re.compile(
        r"(?i)\b(remove|delete|del|drop|truncate|update|rm)\b"
    )),
)


@dataclass(frozen=True)
class Verdict:
    allowed: bool
    reason: str = ""
    rule: str = ""
    command: str = ""
    tool: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)


def _state_dir() -> Path:
    raw = os.environ.get("LODE_STATE_DIR", "").strip()
    return Path(raw) if raw else Path(__file__).resolve().parents[1] / "lode-state"


def log_path(explicit: Optional[str | Path] = None) -> Path:
    if explicit:
        return Path(explicit)
    override = os.environ.get("LODE_COMMAND_REVIEW_LOG", "").strip()
    if override:
        return Path(override)
    return _state_dir() / "command-review.jsonl"


def _append_record(row: Mapping[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(dict(row), ensure_ascii=False) + "\n"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line)


def extract_command(args: Any) -> str:
    """Pull the command string out of a tool-call argument blob."""
    if isinstance(args, str):
        text = args.strip()
        if not text:
            return ""
        try:
            parsed = json.loads(text)
        except (ValueError, TypeError):
            return text
        if isinstance(parsed, (dict, list)):
            return extract_command(parsed)
        return str(parsed).strip()
    if isinstance(args, (list, tuple)):
        parts = [str(item).strip() for item in args if str(item).strip()]
        return " ".join(parts)
    if not isinstance(args, Mapping):
        return str(args or "").strip()
    for key in _COMMAND_KEYS:
        if key not in args:
            continue
        value = args[key]
        if isinstance(value, (list, tuple)):
            return " ".join(str(item) for item in value if str(item).strip())
        text = str(value or "").strip()
        if text:
            return text
    return ""


def review(
    command: str,
    *,
    tool: str = "",
    record: bool = True,
    log: Optional[str | Path] = None,
) -> Verdict:
    """Admit or intercept one complete command. Never calls a model."""
    text = str(command or "").strip()
    tool_name = str(tool or "").strip()
    if not text:
        verdict = Verdict(False, "empty_command", "empty", text, tool_name)
        if record:
            _record(verdict, log)
        return verdict
    for name, pattern in _DENY_RULES:
        if pattern.search(text):
            verdict = Verdict(False, f"command_review:{name}", name, text, tool_name)
            if record:
                _record(verdict, log)
            return verdict
    verdict = Verdict(True, "", "", text, tool_name)
    if record:
        _record(verdict, log)
    return verdict


def _record(verdict: Verdict, log: Optional[str | Path]) -> None:
    try:
        _append_record({
            "at": time.time(),
            "tool": verdict.tool,
            "command": verdict.command,
            "decision": "allowed" if verdict.allowed else f"intercepted:{verdict.rule}",
            "reason": verdict.reason,
            "rule": verdict.rule,
        }, log_path(log))
    except OSError:
        return


def intercept_tool_call(name: str, args: Any, *, log: Optional[str | Path] = None) -> Optional[str]:
    """If this is a shell tool that the regex gate refuses, return the refusal text.

    ``None`` means "not this gate" (not a shell tool, or the command is allowed).
    A hit is recorded and never dispatched.
    """
    tool = str(name or "").strip()
    if tool.lower() not in {item.lower() for item in SHELL_TOOLS}:
        return None
    command = extract_command(args)
    verdict = review(command, tool=tool, record=True, log=log)
    if verdict.allowed:
        return None
    return (
        f"command_review intercepted ({verdict.rule}): {verdict.reason}. "
        "Delete / dump / update never run. This gate does not call a model."
    )


__all__ = [
    "SHELL_TOOLS", "Verdict", "review", "extract_command",
    "intercept_tool_call", "log_path",
]
