"""Thin MCP adapter exposing the 5 guardrail tools.

The logic lives in ``guardrails.tools`` (single source, unit-tested). This file
only registers them as MCP tools so a forked runtime (Strix / pentestagent) calls
them over MCP. Uses the installed official ``mcp`` SDK (mcp.server.fastmcp);
guarded so an API mismatch yields a clear message instead of an import crash.

Run:  python server.py     (stdio MCP server)
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from guardrails import tools  # noqa: E402


def build_server():
    try:
        from mcp.server.fastmcp import FastMCP  # type: ignore
    except Exception as exc:  # pragma: no cover
        raise RuntimeError(
            "mcp.server.fastmcp not importable (%s). Install/upgrade the `mcp` SDK, "
            "or adapt to the lower-level mcp.server.Server API." % exc
        )

    mcp = FastMCP("pentest-agent-guardrails")

    @mcp.tool()
    def policy_grade(action: Dict[str, Any], inert_allowlist_path: Optional[str] = None,
                     ledger_path: Optional[str] = None) -> Dict[str, Any]:
        """Grade an ActionCard (A0..F0 + red-team-hardened refine)."""
        return tools.policy_grade(action, inert_allowlist_path=inert_allowlist_path, ledger_path=ledger_path)

    @mcp.tool()
    def gateway_request(action: Dict[str, Any], execute: bool = False,
                        inert_allowlist_path: Optional[str] = None,
                        ledger_path: Optional[str] = None) -> Dict[str, Any]:
        """Sole-egress request tool; pre-gates via policy_grade."""
        return tools.gateway_request(action, execute=execute,
                                     inert_allowlist_path=inert_allowlist_path, ledger_path=ledger_path)

    @mcp.tool()
    def human_gate(need_human_card: Dict[str, Any]) -> Dict[str, Any]:
        """Request human approval (fail-closed: no external authority wired)."""
        return tools.human_gate(need_human_card)

    @mcp.tool()
    def record_evidence(evidence: Dict[str, Any]) -> Dict[str, Any]:
        """Record a request/response evidence pair (delegates to reused layer)."""
        return tools.record_evidence(evidence)

    @mcp.tool()
    def verify_finding(evidence_dir: str) -> Dict[str, Any]:
        """Independent second review (must be a different model in prod)."""
        return tools.verify_finding(evidence_dir)

    return mcp


def main() -> int:
    try:
        server = build_server()
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    server.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
