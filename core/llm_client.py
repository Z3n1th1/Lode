"""The single LLM client: transport, tier routing, failover and the tool loop.

Provider parsing, tier routing (``prefer``/``only``) and cross-provider failover
live in :mod:`core.llm_pool`. This module owns the *transport* on top of it:

* :func:`complete_messages` — one OpenAI-compatible call for a full message list
  (+ optional ``tools``), returning the raw assistant message. Uses ``httpx``
  when available (robust on Windows, connection reuse), else the stdlib urllib
  path in :mod:`core.llm_pool`.
* :func:`run_tool_loop` — the OpenAI function-calling loop (used by the
  interactive chat). Preserves the protocol guard from :func:`sanitize_messages`
  and the per-round call cap, which are what keep providers from 400-ing.

Every HTTP-to-LLM call in the product goes through here: ``agents.src_agent``
(plain completion) and ``agents.src_chat`` (tool loop).
"""
from __future__ import annotations

import json
import time
from typing import Any, Callable, Dict, List, Optional

from core.llm_pool import (
    DEFAULT_MODEL,
    _endpoint_paths,
    complete_messages as _urllib_complete_messages,
    messages_payload,
    ordered_pool,
)

MAX_TOOL_ROUNDS = 6
# Each tool_call in the assistant message MUST get a matching `tool` response,
# otherwise the next request fails with 400 ("must be followed by tool messages
# responding to each tool_call_id"). We therefore cap the number of calls we
# advertise in the assistant message to what we are willing to answer.
MAX_TOOL_CALLS_PER_ROUND = 8

_LAST_ERROR = {"error": ""}


def last_error() -> str:
    """Reason the last failed call failed (never contains an api key)."""
    return str(_LAST_ERROR.get("error") or "")


def clear_error() -> None:
    _LAST_ERROR["error"] = ""


def sanitize_messages(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Drop protocol-invalid tool messages so the request always validates.

    OpenAI-style providers require that every assistant message with
    ``tool_calls`` is immediately followed by one ``tool`` message per call id.
    Corrupted history (a truncated round, a process kill mid-round, or an old
    session written before this guard existed) would otherwise poison every
    subsequent turn. This rebuilds a valid sequence: an assistant tool_calls
    message with incomplete responses is downgraded to plain text, and orphan
    ``tool`` messages are dropped.
    """
    out: List[Dict[str, Any]] = []
    i, n = 0, len(messages)
    while i < n:
        m = messages[i]
        role = m.get("role")
        if role == "assistant" and m.get("tool_calls"):
            needed = [str(c.get("id", "")) for c in m["tool_calls"]]
            j = i + 1
            following: List[Dict[str, Any]] = []
            while j < n and messages[j].get("role") == "tool":
                following.append(messages[j])
                j += 1
            got = {str(t.get("tool_call_id", "")) for t in following}
            if all(cid in got for cid in needed):
                out.append(m)
                out.extend(following)
            else:
                text = str(m.get("content") or "").strip()
                if text:
                    out.append({"role": "assistant", "content": text})
            i = j
            continue
        if role == "tool":
            # Orphan tool message with no preceding tool_calls message.
            i += 1
            continue
        out.append(m)
        i += 1
    return out


def _httpx_provider(httpx: Any, provider: Dict[str, str], messages: List[Dict[str, Any]],
                    tools: Any, timeout: float, max_tokens: int,
                    temperature: float) -> "tuple[Optional[Dict[str, Any]], str]":
    """One provider via httpx with retry + endpoint fallback + tools-strip.

    Returns ``(message, "")`` on success or ``(None, error)``. Transient network
    errors (WinError 10053/10054, timeouts) and 5xx are retried up to 3 times.
    """
    base = str(provider.get("base_url") or "").rstrip("/")
    key = str(provider.get("api_key") or "").strip()
    model = str(provider.get("model") or "").strip() or DEFAULT_MODEL
    if not base or not key:
        return None, "missing_base_url_or_api_key"
    paths = _endpoint_paths(base)
    active_tools = tools
    last = "unknown"
    for attempt in range(3):
        retry = False
        for index, path in enumerate(paths):
            body = messages_payload(model, messages, active_tools,
                                    max_tokens=max_tokens, temperature=temperature)
            try:
                with httpx.Client(timeout=timeout, verify=True) as client:
                    resp = client.post(
                        base + path,
                        headers={"Content-Type": "application/json",
                                 "Authorization": f"Bearer {key}"},
                        content=body,
                    )
            except Exception as exc:  # noqa: BLE001 - transient network error
                last = f"{type(exc).__name__}: {str(exc)[:200]}"
                retry = True
                break
            if resp.status_code == 200:
                try:
                    parsed = resp.json()
                except Exception:  # noqa: BLE001
                    last = f"invalid json: {resp.text[:200]}"
                    retry = True
                    break
                message = (parsed.get("choices") or [{}])[0].get("message") or {}
                if message:
                    return message, ""
                last = f"empty choices: {resp.text[:200]}"
                retry = True
                break
            if resp.status_code in (401, 404) and index != len(paths) - 1:
                continue  # endpoint-path difference: try the other path
            if active_tools and resp.status_code in (400, 422):
                active_tools = None  # provider rejects tools; retry plain
                continue
            if resp.status_code >= 500:
                last = f"HTTP {resp.status_code}: {resp.text[:200]}"
                retry = True
                break
            return None, f"HTTP {resp.status_code}: {resp.text[:300]}"
        if retry and attempt < 2:
            time.sleep(1.5 * (attempt + 1))
            continue
        break
    return None, last


def complete_messages(messages: List[Dict[str, Any]], *, tools: Any = None,
                      timeout: float = 90.0, prefer: str = "", only: bool = False,
                      max_tokens: int = 4096, temperature: float = 0.3,
                      ) -> Optional[Dict[str, Any]]:
    """Full-message completion with tier routing and cross-provider failover.

    Returns the raw assistant message dict, or ``None`` on failure (see
    :func:`last_error`). httpx is preferred; without it this falls back to the
    stdlib urllib transport in :mod:`core.llm_pool`.
    """
    pool = ordered_pool(prefer, only)
    if not pool:
        _LAST_ERROR["error"] = "no provider configured (LLM_PROVIDERS / LLM_API_KEY)"
        return None
    try:
        import httpx
    except ImportError:
        message = _urllib_complete_messages(
            messages, tools=tools, timeout=timeout, prefer=prefer, only=only,
            max_tokens=max_tokens, temperature=temperature,
        )
        if message is None:
            _LAST_ERROR["error"] = _LAST_ERROR.get("error") or "urllib transport failed"
        else:
            clear_error()
        return message
    last = ""
    for provider in pool:
        message, error = _httpx_provider(httpx, provider, messages, tools, timeout,
                                         max_tokens, temperature)
        if message is not None:
            clear_error()
            return message
        last = error or last
    _LAST_ERROR["error"] = last or "unknown"
    return None


def run_tool_loop(
    messages: List[Dict[str, Any]],
    *,
    tools: List[Dict[str, Any]],
    dispatch: Callable[[str, Dict[str, Any]], str],
    max_rounds: int = MAX_TOOL_ROUNDS,
    max_calls_per_round: int = MAX_TOOL_CALLS_PER_ROUND,
    timeout: float = 90.0,
    complete_fn: Optional[Callable[..., Optional[Dict[str, Any]]]] = None,
    on_tool_call: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    on_tool_result: Optional[Callable[[str, Dict[str, Any], str], None]] = None,
) -> Dict[str, Any]:
    """OpenAI function-calling loop.

    Returns ``{"text", "messages", "rounds", "error", "stopped"}``. ``text`` is
    the final assistant text; ``error`` is set (with ``text=""``) when an LLM
    call failed. ``complete_fn`` is the injectable completion seam (defaults to
    :func:`complete_messages`); it is called as ``complete_fn(messages,
    tools=..., timeout=...)``.
    """
    complete = complete_fn or complete_messages
    working: List[Dict[str, Any]] = list(messages)

    for round_index in range(max_rounds):
        message = complete(working, tools=tools, timeout=timeout)
        if message is None:
            return {"text": "", "messages": working, "rounds": round_index,
                    "error": last_error(), "stopped": False}
        tool_calls = message.get("tool_calls") or []
        content = str(message.get("content") or "").strip()
        if not tool_calls:
            return {"text": content, "messages": working, "rounds": round_index + 1,
                    "error": "", "stopped": False}

        # Trim first so the assistant message only declares calls we will answer
        # — otherwise the extra calls are orphaned and the next request 400s.
        calls = tool_calls[:max_calls_per_round]
        working.append({"role": "assistant", "content": content, "tool_calls": calls})
        for call in calls:
            fn = call.get("function") or {}
            name = str(fn.get("name", ""))
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            if on_tool_call is not None:
                on_tool_call(name, args)
            result = dispatch(name, args)
            if on_tool_result is not None:
                on_tool_result(name, args, result)
            working.append({
                "role": "tool",
                "tool_call_id": str(call.get("id", "")),
                "content": str(result)[:8000],
            })

    # Tool rounds exhausted — ask once more for a summary (no tools).
    working.append({"role": "user", "content": "Summarize what you found so far."})
    message = complete(working, tools=None, timeout=timeout)
    text = (message.get("content", "") if message else "Tool execution limit reached.").strip()
    return {"text": text, "messages": working, "rounds": max_rounds,
            "error": "" if message else last_error(), "stopped": True}


__all__ = [
    "MAX_TOOL_ROUNDS",
    "MAX_TOOL_CALLS_PER_ROUND",
    "complete_messages",
    "run_tool_loop",
    "sanitize_messages",
    "last_error",
    "clear_error",
]
