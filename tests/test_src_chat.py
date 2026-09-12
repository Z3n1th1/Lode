"""Regression tests for the tool-calling protocol guard in agents.src_chat.

Background: OpenAI-style providers reject a request when an assistant message
with `tool_calls` is not immediately followed by one `tool` message per
`tool_call_id` (HTTP 400 "must be followed by tool messages ..."). The chat
loop used to answer only the first 4 tool calls, so any turn where the model
emitted more than 4 calls produced a permanently invalid history.
"""
from __future__ import annotations

from typing import Any, Dict, List

import agents.src_chat as sc
from agents.src_chat import (
    MAX_TOOL_CALLS_PER_ROUND,
    SrcChatSession,
    _sanitize_messages,
    chat,
)


def _assert_protocol_valid(messages: List[Dict[str, Any]]) -> None:
    """Every assistant tool_calls message must be answered by tool messages."""
    i = 0
    while i < len(messages):
        m = messages[i]
        if m.get("role") == "assistant" and m.get("tool_calls"):
            needed = [str(c.get("id", "")) for c in m["tool_calls"]]
            j = i + 1
            got = []
            while j < len(messages) and messages[j].get("role") == "tool":
                got.append(str(messages[j].get("tool_call_id", "")))
                j += 1
            missing = [c for c in needed if c not in got]
            assert not missing, f"assistant tool_calls unanswered: {missing}"
            i = j
            continue
        # A tool message must never appear without a preceding tool_calls block.
        assert m.get("role") != "tool", "orphan tool message in payload"
        i += 1


def test_sanitize_keeps_complete_round() -> None:
    msgs = [
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": "", "tool_calls": [
            {"id": "a", "type": "function", "function": {"name": "f", "arguments": "{}"}},
            {"id": "b", "type": "function", "function": {"name": "f", "arguments": "{}"}},
        ]},
        {"role": "tool", "tool_call_id": "a", "content": "1"},
        {"role": "tool", "tool_call_id": "b", "content": "2"},
        {"role": "assistant", "content": "done"},
    ]
    out = _sanitize_messages(msgs)
    assert out == msgs
    _assert_protocol_valid(out)


def test_sanitize_downgrades_incomplete_tool_calls() -> None:
    msgs = [
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": "partial answer", "tool_calls": [
            {"id": "a", "type": "function", "function": {"name": "f", "arguments": "{}"}},
            {"id": "b", "type": "function", "function": {"name": "f", "arguments": "{}"}},
        ]},
        {"role": "tool", "tool_call_id": "a", "content": "1"},  # b never answered
        {"role": "assistant", "content": "done"},
    ]
    out = _sanitize_messages(msgs)
    assert [m["role"] for m in out] == ["user", "assistant", "assistant"]
    assert out[1] == {"role": "assistant", "content": "partial answer"}
    _assert_protocol_valid(out)


def test_sanitize_drops_orphan_tool_messages() -> None:
    msgs = [
        {"role": "user", "content": "hi"},
        {"role": "tool", "tool_call_id": "ghost", "content": "x"},
        {"role": "assistant", "content": "done"},
    ]
    out = _sanitize_messages(msgs)
    assert [m["role"] for m in out] == ["user", "assistant"]


def test_chat_answers_every_tool_call(monkeypatch) -> None:
    """A turn with more tool calls than the per-round cap must still be valid."""
    emitted = {"n": 0}
    captured: List[List[Dict[str, Any]]] = []

    def fake_llm(messages, *, tools=None, timeout=90.0):  # noqa: ANN001
        captured.append(messages)
        emitted["n"] += 1
        if emitted["n"] == 1:
            return {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {"id": f"call_{i}", "type": "function",
                     "function": {"name": "show_progress", "arguments": "{}"}}
                    for i in range(MAX_TOOL_CALLS_PER_ROUND + 4)
                ],
            }
        return {"role": "assistant", "content": "done"}

    monkeypatch.setattr(sc, "_llm_call", fake_llm)

    session = SrcChatSession(session_id="test-session")
    reply = chat(session, "fuzz a bunch of params")

    assert reply == "done"
    # The second LLM request carries the tool round; it must be protocol-valid
    # and must not advertise more calls than we are willing to answer.
    second = captured[1]
    _assert_protocol_valid(second)
    assistant_tc = [m for m in second if m.get("role") == "assistant" and m.get("tool_calls")]
    assert len(assistant_tc) == 1
    assert len(assistant_tc[0]["tool_calls"]) == MAX_TOOL_CALLS_PER_ROUND
    tool_msgs = [m for m in second if m.get("role") == "tool"]
    assert len(tool_msgs) == MAX_TOOL_CALLS_PER_ROUND
