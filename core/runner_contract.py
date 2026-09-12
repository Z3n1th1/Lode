"""Shared terminal contract for runners that did not obtain execution capability."""
from __future__ import annotations


_ALLOWED_BLOCK_REASONS = frozenset(
    {
        "external_tool_runner_unconfigured",
        "synthetic_no_execution",
        "backend_capability_unavailable",
    }
)


class RunnerBlockedError(RuntimeError):
    """Typed, sanitized signal that a runner did not execute a tool."""

    def __init__(self, code: str) -> None:
        self.code = code if type(code) is str and code in _ALLOWED_BLOCK_REASONS else "runner_blocked"
        super().__init__(self.code)
