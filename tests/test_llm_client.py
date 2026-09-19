"""Tests for core.llm_client — the single tool-calling LLM transport.

Covers the httpx transport (success, tools-strip on 400/422, 5xx retry,
endpoint-path fallback), tier routing via core.llm_pool.ordered_pool, and the
function-calling loop's protocol guarantees.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
import types
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT))
sys.path.insert(0, str(_PROJECT_ROOT / "core"))

from core import llm_client  # noqa: E402
from core import llm_pool  # noqa: E402

POOL = [
    {"name": "cheap", "base_url": "https://cheap.test", "api_key": "k-cheap", "model": "mini"},
    {"name": "smart", "base_url": "https://smart.test", "api_key": "k-smart", "model": "max"},
]


class _Resp:
    def __init__(self, status: int, payload: Optional[Dict[str, Any]] = None, text: str = ""):
        self.status_code = status
        self._payload = payload
        self.text = text or (json.dumps(payload) if payload is not None else "")

    def json(self) -> Dict[str, Any]:
        if self._payload is None:
            raise ValueError("no json body")
        return self._payload


def _ok(content: str = "ok") -> _Resp:
    return _Resp(200, {"choices": [{"message": {"role": "assistant", "content": content}}]})


def _fake_httpx(script: List[Any], log: List[Dict[str, Any]]) -> types.SimpleNamespace:
    """Build a fake ``httpx`` module. ``script`` items are responses or callables."""
    queue = list(script)

    class _Client:
        def __init__(self, timeout=None, verify=None):  # noqa: ANN001
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def post(self, url, headers=None, content=None):  # noqa: ANN001
            body = json.loads(content.decode("utf-8")) if isinstance(content, bytes) else content
            log.append({"url": url, "body": body})
            item = queue.pop(0) if queue else _Resp(500, text="script exhausted")
            return item(url, body) if callable(item) else item

    return types.SimpleNamespace(Client=_Client)


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self._pool_patch = patch.object(llm_pool, "provider_pool", lambda: [dict(p) for p in POOL])
        self._pool_patch.start()
        self.addCleanup(self._pool_patch.stop)
        llm_client.clear_error()

    def _with_httpx(self, script: List[Any]):
        log: List[Dict[str, Any]] = []
        return log, patch.dict(sys.modules, {"httpx": _fake_httpx(script, log)})


class OrderedPoolTests(unittest.TestCase):
    def test_prefer_promotes_match_to_front(self) -> None:
        with patch.object(llm_pool, "provider_pool", lambda: [dict(p) for p in POOL]):
            ordered = llm_pool.ordered_pool("smart")
        self.assertEqual(["smart", "cheap"], [p["name"] for p in ordered])

    def test_only_restricts_to_matches(self) -> None:
        with patch.object(llm_pool, "provider_pool", lambda: [dict(p) for p in POOL]):
            ordered = llm_pool.ordered_pool("smart", only=True)
        self.assertEqual(["smart"], [p["name"] for p in ordered])
        with patch.object(llm_pool, "provider_pool", lambda: [dict(p) for p in POOL]):
            self.assertEqual([], llm_pool.ordered_pool("nope", only=True))


class CompleteMessagesTests(_Base):
    def test_success_returns_assistant_message(self) -> None:
        log, httpx_patch = self._with_httpx([_ok("hello")])
        with httpx_patch:
            message = llm_client.complete_messages([{"role": "user", "content": "hi"}])
        self.assertIsNotNone(message)
        self.assertEqual("hello", message["content"])
        self.assertEqual("", llm_client.last_error())
        # cheap first in the pool -> first request goes to cheap.test
        self.assertIn("cheap.test", log[0]["url"])

    def test_tier_routing_prefers_smart(self) -> None:
        log, httpx_patch = self._with_httpx([_ok()])
        with httpx_patch:
            llm_client.complete_messages([{"role": "user", "content": "hi"}], prefer="smart")
        self.assertIn("smart.test", log[0]["url"])
        self.assertEqual("max", log[0]["body"]["model"])

    def test_tools_stripped_and_retried_on_400(self) -> None:
        log, httpx_patch = self._with_httpx([_Resp(400, text="tools unsupported"), _ok("plain")])
        with httpx_patch:
            message = llm_client.complete_messages(
                [{"role": "user", "content": "hi"}],
                tools=[{"type": "function", "function": {"name": "f"}}],
            )
        self.assertEqual("plain", message["content"])
        self.assertIn("tools", log[0]["body"])
        self.assertNotIn("tools", log[1]["body"])

    def test_transient_5xx_is_retried(self) -> None:
        log, httpx_patch = self._with_httpx([_Resp(503, text="down"), _ok("recovered")])
        with httpx_patch, patch.object(llm_client.time, "sleep", lambda *_: None):
            message = llm_client.complete_messages([{"role": "user", "content": "hi"}])
        self.assertEqual("recovered", message["content"])
        self.assertEqual(2, len(log))

    def test_endpoint_path_fallback_on_401(self) -> None:
        # base_url without /v1 -> paths are /v1/chat/completions then /chat/completions
        log, httpx_patch = self._with_httpx([_Resp(401, text="unauthorized"), _ok("second-path")])
        with httpx_patch:
            message = llm_client.complete_messages([{"role": "user", "content": "hi"}])
        self.assertEqual("second-path", message["content"])
        self.assertTrue(log[0]["url"].endswith("/v1/chat/completions"))
        self.assertTrue(log[1]["url"].endswith("/chat/completions"))

    def test_failover_to_next_provider(self) -> None:
        def fail_first(url, body):
            if "cheap.test" in url:
                return _Resp(403, text="forbidden")
            return _ok("from-smart")

        log, httpx_patch = self._with_httpx([fail_first, fail_first])
        with httpx_patch:
            message = llm_client.complete_messages([{"role": "user", "content": "hi"}])
        self.assertEqual("from-smart", message["content"])
        self.assertEqual(2, len(log))

    def test_no_provider_sets_error_and_returns_none(self) -> None:
        with patch.object(llm_pool, "provider_pool", lambda: []):
            self.assertIsNone(llm_client.complete_messages([{"role": "user", "content": "hi"}]))
        self.assertIn("no provider", llm_client.last_error())


class RunToolLoopTests(_Base):
    def test_no_tool_calls_returns_text(self) -> None:
        def complete(messages, *, tools=None, timeout=90.0):  # noqa: ANN001
            return {"role": "assistant", "content": "just text"}

        result = llm_client.run_tool_loop(
            [{"role": "user", "content": "hi"}], tools=[], dispatch=lambda n, a: "x",
            complete_fn=complete,
        )
        self.assertEqual("just text", result["text"])
        self.assertEqual("", result["error"])

    def test_trims_calls_to_cap_and_answers_each(self) -> None:
        seen: List[List[Dict[str, Any]]] = []
        calls = {"n": 0}

        def complete(messages, *, tools=None, timeout=90.0):  # noqa: ANN001
            seen.append(messages)
            calls["n"] += 1
            if calls["n"] == 1:
                return {"role": "assistant", "content": "", "tool_calls": [
                    {"id": f"c{i}", "type": "function", "function": {"name": "f", "arguments": "{}"}}
                    for i in range(llm_client.MAX_TOOL_CALLS_PER_ROUND + 3)
                ]}
            return {"role": "assistant", "content": "done"}

        result = llm_client.run_tool_loop(
            [{"role": "user", "content": "hi"}], tools=[{"x": 1}],
            dispatch=lambda n, a: "result", complete_fn=complete,
        )
        self.assertEqual("done", result["text"])
        second = seen[1]
        assistant_tc = [m for m in second if m.get("role") == "assistant" and m.get("tool_calls")]
        self.assertEqual(1, len(assistant_tc))
        self.assertEqual(llm_client.MAX_TOOL_CALLS_PER_ROUND, len(assistant_tc[0]["tool_calls"]))
        tool_msgs = [m for m in second if m.get("role") == "tool"]
        self.assertEqual(llm_client.MAX_TOOL_CALLS_PER_ROUND, len(tool_msgs))

    def test_rounds_exhausted_summarizes_without_tools(self) -> None:
        seen: List[Optional[Any]] = []

        def complete(messages, *, tools=None, timeout=90.0):  # noqa: ANN001
            seen.append(tools)
            return {"role": "assistant", "content": "", "tool_calls": [
                {"id": "c0", "type": "function", "function": {"name": "f", "arguments": "{}"}}]}

        result = llm_client.run_tool_loop(
            [{"role": "user", "content": "hi"}], tools=[{"x": 1}],
            dispatch=lambda n, a: "r", complete_fn=complete,
            max_rounds=2,
        )
        self.assertTrue(result["stopped"])
        # last call (the summary) must not advertise tools
        self.assertIsNone(seen[-1])

    def test_failure_returns_error_with_empty_text(self) -> None:
        from unittest.mock import patch as _patch

        with _patch.object(llm_client, "last_error", lambda: "boom"):
            result = llm_client.run_tool_loop(
                [{"role": "user", "content": "hi"}], tools=[],
                dispatch=lambda n, a: "x", complete_fn=lambda *a, **k: None,
            )
        self.assertEqual("", result["text"])
        self.assertEqual("boom", result["error"])


class UpstreamConcurrencyTests(unittest.TestCase):
    """按上游限并发:并发 worker 不等于并发打同一家 provider。

    没有任何闸的时候,把 job 池从 2 提到 8 就等于"同时对一家上游发 8 个(再乘
    每个 cycle 并行的 explore 数)请求",那是收集 429 的标准做法。
    """

    def setUp(self) -> None:
        os.environ.pop("LODE_LLM_CONCURRENCY", None)
        llm_client._GATES.clear()
        self.addCleanup(os.environ.pop, "LODE_LLM_CONCURRENCY", None)
        self.addCleanup(llm_client._GATES.clear)

    def _hammer(self, host: str, threads: int, cap: int) -> int:
        """Run `threads` concurrent completions at one upstream; return peak overlap."""
        live = 0
        peak = 0
        lock = threading.Lock()
        provider = {"name": "p", "base_url": f"https://{host}", "api_key": "k", "model": "m"}

        def fake_provider(httpx, provider, messages, tools, timeout, max_tokens, temperature):
            nonlocal live, peak
            with lock:
                live += 1
                peak = max(peak, live)
            time.sleep(0.15)
            with lock:
                live -= 1
            return {"role": "assistant", "content": "ok"}, ""

        os.environ["LODE_LLM_CONCURRENCY"] = str(cap)
        with patch.object(llm_client, "_httpx_provider", fake_provider), \
                patch.object(llm_client, "ordered_pool", lambda prefer, only: [provider]):
            workers = [threading.Thread(target=llm_client.complete_messages,
                                        args=([{"role": "user", "content": "hi"}],))
                       for _ in range(threads)]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join()
        return peak

    def test_one_upstream_never_exceeds_the_cap(self) -> None:
        self.assertLessEqual(self._hammer("one.test", threads=6, cap=2), 2)

    def test_two_upstreams_have_their_own_gates(self) -> None:
        """两家上游各 2 个并发 → 合起来 4 个同时在飞。闸按上游分,不是全局一条。"""
        peaks = [self._hammer(f"up{i}.test", threads=2, cap=2) for i in range(2)]
        self.assertEqual([2, 2], peaks)

    def test_the_env_var_sets_the_cap(self) -> None:
        os.environ["LODE_LLM_CONCURRENCY"] = "3"
        self.assertEqual(3, llm_client.configured_llm_concurrency())

    def test_garbage_and_absurd_values_fall_back(self) -> None:
        os.environ["LODE_LLM_CONCURRENCY"] = "lots"
        self.assertEqual(llm_client.DEFAULT_LLM_CONCURRENCY,
                         llm_client.configured_llm_concurrency())
        os.environ["LODE_LLM_CONCURRENCY"] = "0"
        self.assertEqual(1, llm_client.configured_llm_concurrency())
        os.environ["LODE_LLM_CONCURRENCY"] = "9999"
        self.assertEqual(64, llm_client.configured_llm_concurrency())


if __name__ == "__main__":
    unittest.main()
