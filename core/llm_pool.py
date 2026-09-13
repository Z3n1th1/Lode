"""Self-contained LLM provider pool (stdlib only).

This module owns provider parsing and routing. It is the single source of the
provider pool, tier routing and failover used by the SRC agent and (through
:mod:`core.llm_client`) by the interactive chat:

* providers come from ``LLM_PROVIDERS="name|base_url|api_key|model,..."`` or the
  legacy single-key trio ``LLM_API_KEY``/``LLM_BASE_URL``/``LLM_MODEL``;
* ``prefer`` / ``only`` implement the tier routing (smart Reasoner vs cheap
  Explorer) that :class:`agents.src_agent.AgentConfig` has always passed down;
* providers are tried in order with endpoint-path fallback, so one dead provider
  fails over to the next without killing the run;
* the runtime "active provider" file stays compatible with what the Console
  writes (``LLM_ACTIVE_PROVIDER_FILE`` -> ``model_active_provider.json``).

Credential discipline: keys are read from the environment / local settings file
only, and are never written to logs or returned to callers.
"""
from __future__ import annotations

import json
import os

from core.file_lock import replace_with_retry

import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_BASE_URL = "https://api.deepseek.com"
DEFAULT_MODEL = "deepseek-chat"
MAX_RESPONSE_BYTES = 512_000


def legacy_config() -> Dict[str, str]:
    """The pre-pool single-provider env trio."""
    return {
        "api_key": os.environ.get("LLM_API_KEY", "").strip(),
        "base_url": os.environ.get("LLM_BASE_URL", DEFAULT_BASE_URL).strip().rstrip("/") or DEFAULT_BASE_URL,
        "model": os.environ.get("LLM_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL,
    }


def parse_providers() -> List[Dict[str, str]]:
    """Parse the ``LLM_PROVIDERS`` pool, falling back to the legacy trio.

    Groups with the wrong field count or an empty key are dropped, matching the
    documented format (a keyless provider could never be called anyway).
    """
    providers: List[Dict[str, str]] = []
    raw = os.environ.get("LLM_PROVIDERS", "").strip()
    if raw:
        for index, group in enumerate(raw.split(",")):
            parts = [part.strip() for part in group.split("|")]
            if len(parts) != 4:
                continue
            name, base, key, model = parts
            if not key:
                continue
            providers.append({
                "name": name or f"provider-{index}",
                "base_url": (base or DEFAULT_BASE_URL).rstrip("/"),
                "api_key": key,
                "model": model or DEFAULT_MODEL,
            })
    if not providers:
        cfg = legacy_config()
        if cfg["api_key"]:
            providers.append({
                "name": "default",
                "base_url": cfg["base_url"],
                "api_key": cfg["api_key"],
                "model": cfg["model"],
            })
    return providers


def active_provider_file() -> Path:
    """Runtime active-provider file (``LLM_ACTIVE_PROVIDER_FILE`` wins)."""
    raw = os.environ.get("LLM_ACTIVE_PROVIDER_FILE", "").strip()
    if raw:
        return Path(raw)
    state_dir = os.environ.get("LODE_STATE_DIR", "").strip()
    base = Path(state_dir) if state_dir else Path(__file__).resolve().parents[1] / "lode-state"
    return base / "model_active_provider.json"


def get_active_provider_name() -> str:
    """Name of the runtime-selected provider, or "" when unset/unreadable."""
    try:
        doc = json.loads(active_provider_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    if not isinstance(doc, dict):
        return ""
    return str(doc.get("name") or "").strip()


def set_active_provider(name: str) -> Optional[Dict[str, str]]:
    """Promote a provider to the front of the failover order (no key stored)."""
    name = str(name or "").strip()
    match = next((p for p in parse_providers() if p.get("name") == name), None)
    if match is None:
        return None
    path = active_provider_file()
    doc = {"name": match["name"], "model": match["model"], "set_at": time.time(), "set_by": "llm_pool"}
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        staged = path.with_name("." + path.name + ".tmp")
        staged.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
        replace_with_retry(staged, path)
    except OSError:
        return None
    return {"name": match["name"], "model": match["model"]}


def provider_pool() -> List[Dict[str, str]]:
    """The pool with the runtime-active provider promoted to the front."""
    providers = parse_providers()
    active = get_active_provider_name()
    if not active:
        return providers
    for index, provider in enumerate(providers):
        if provider.get("name") == active:
            return [provider] + providers[:index] + providers[index + 1:]
    return providers


def ordered_pool(prefer: str = "", only: bool = False) -> List[Dict[str, str]]:
    """The pool ordered for one call: active provider first, tier matches next.

    ``prefer`` is a case-insensitive substring matched against ``name + model``;
    matches are promoted to the front. ``only=True`` restricts the result to the
    matches (no failover to a different model). Shared by :func:`complete` and
    :func:`complete_messages`, and by :mod:`core.llm_client`.
    """
    pool = provider_pool()
    if not pool or not prefer:
        return pool
    needle = prefer.lower()
    match = [p for p in pool if needle in (str(p.get("name")) + str(p.get("model"))).lower()]
    return match if only else (match + [p for p in pool if p not in match])


def _endpoint_paths(base_url: str) -> List[str]:
    """Some gateways expose /chat/completions, others only /v1/chat/completions."""
    return ["/chat/completions"] if base_url.endswith("/v1") else [
        "/v1/chat/completions", "/chat/completions"]


def _post(url: str, body: bytes, api_key: str, timeout: float) -> Dict[str, Any]:
    request = urllib.request.Request(url, data=body, headers={
        "Content-Type": "application/json",
        "Authorization": "Bearer " + api_key,
    })
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read(MAX_RESPONSE_BYTES).decode("utf-8"))


def _chat_payload(model: str, system: str, user: str, *, max_tokens: int = 2048,
                  temperature: float = 0.2) -> bytes:
    return json.dumps({
        "model": model,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }).encode("utf-8")


def _try_provider(provider: Dict[str, str], body_for: Any, timeout: float) -> Optional[Dict[str, Any]]:
    """One provider, with endpoint-path fallback. ``body_for(model) -> bytes``."""
    base = str(provider.get("base_url") or "").rstrip("/")
    key = str(provider.get("api_key") or "").strip()
    model = str(provider.get("model") or "").strip() or DEFAULT_MODEL
    if not base or not key:
        return None
    paths = _endpoint_paths(base)
    for index, path in enumerate(paths):
        try:
            return _post(base + path, body_for(model), key, timeout)
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 404) and index != len(paths) - 1:
                continue  # 端点路径差异：换另一条再试
            return None
        except Exception:  # noqa: BLE001 - 网络/解析错误：换下一个 provider
            return None
    return None


def messages_payload(model: str, messages: List[Dict[str, Any]], tools: Any = None, *,
                     max_tokens: int = 4096, temperature: float = 0.3) -> bytes:
    """OpenAI-compatible chat body for a full message list (+ optional tools)."""
    body: Dict[str, Any] = {
        "model": model,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "messages": messages,
    }
    if tools:
        body["tools"] = tools
    return json.dumps(body).encode("utf-8")


def _try_provider_message(provider: Dict[str, str], messages: List[Dict[str, Any]],
                          tools: Any, timeout: float, max_tokens: int,
                          temperature: float) -> Optional[Dict[str, Any]]:
    """One provider for a message list, with endpoint fallback + tools-strip.

    Some providers reject a ``tools`` payload with 400/422 (unsupported feature);
    retrying once without tools keeps a tool-capable request viable on them.
    """
    base = str(provider.get("base_url") or "").rstrip("/")
    key = str(provider.get("api_key") or "").strip()
    model = str(provider.get("model") or "").strip() or DEFAULT_MODEL
    if not base or not key:
        return None
    paths = _endpoint_paths(base)
    active_tools = tools
    for index, path in enumerate(paths):
        body = messages_payload(model, messages, active_tools,
                                max_tokens=max_tokens, temperature=temperature)
        try:
            payload = _post(base + path, body, key, timeout)
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 404) and index != len(paths) - 1:
                continue
            if active_tools and exc.code in (400, 422):
                active_tools = None  # provider can't do tools; retry plain
                continue
            return None
        except Exception:  # noqa: BLE001
            return None
        message = ((payload.get("choices") or [{}])[0].get("message") or {})
        if message:
            return message
        return None
    return None


def complete_messages(messages: List[Dict[str, Any]], *, tools: Any = None,
                      timeout: float = 90.0, prefer: str = "", only: bool = False,
                      max_tokens: int = 4096, temperature: float = 0.3,
                      ) -> Optional[Dict[str, Any]]:
    """Message-list completion with tier routing, failover and tool support.

    Returns the raw assistant message dict (``{role, content, tool_calls?}``) or
    ``None`` when the pool is empty / every provider failed. This is the
    stdlib-only sibling of :func:`complete`; :mod:`core.llm_client` prefers an
    httpx transport and falls back to this.
    """
    pool = ordered_pool(prefer, only)
    if not pool:
        return None
    for provider in pool:
        message = _try_provider_message(provider, messages, tools, timeout, max_tokens, temperature)
        if message is not None:
            return message
    return None


def complete(system: str, user: str, *, timeout: float = 60.0, prefer: str = "",
             only: bool = False) -> Optional[str]:
    """One-shot completion with tier routing and cross-provider failover.

    ``prefer`` is a case-insensitive substring matched against ``name + model``
    and promotes matches to the front; ``only=True`` restricts the call to those
    matches (no failover to a different model). Returns ``None`` when the pool is
    empty or every provider failed.
    """
    pool = ordered_pool(prefer, only)
    if not pool:
        return None
    for provider in pool:
        payload = _try_provider(
            provider,
            lambda model: _chat_payload(model, system, user),
            timeout,
        )
        if payload is None:
            continue
        message = ((payload.get("choices") or [{}])[0].get("message") or {})
        text = str(message.get("content") or "").strip()
        if text:
            return text
    return None


def probe_provider(provider: Dict[str, str], *, timeout: float = 15.0) -> Dict[str, Any]:
    """Connectivity probe for one provider (Console "测试" button).

    Unlike :func:`complete` this keeps the *reason* for a failure — HTTP status
    or exception type — because "401" and "wrong endpoint path" need different
    fixes. Never returns or logs the api_key; a failure is a normal result
    (``ok=False`` plus a short ``error``), not an exception.
    """
    result: Dict[str, Any] = {
        "name": str(provider.get("name") or "?"),
        "model": str(provider.get("model") or "").strip() or DEFAULT_MODEL,
        "ok": False,
        "latency_ms": 0,
        "error": "",
    }
    base = str(provider.get("base_url") or "").rstrip("/")
    key = str(provider.get("api_key") or "").strip()
    if not base or not key:
        result["error"] = "missing_base_url_or_api_key"
        return result
    paths = _endpoint_paths(base)
    started = time.monotonic()
    for index, path in enumerate(paths):
        try:
            _post(
                base + path,
                _chat_payload(result["model"], "", "ping", max_tokens=1, temperature=0.0),
                key,
                timeout,
            )
            result["ok"] = True
            break
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 404) and index != len(paths) - 1:
                continue
            result["error"] = f"http_{exc.code}"
        except Exception as exc:  # noqa: BLE001 - 只回传简短原因，绝不带 key
            result["error"] = f"{type(exc).__name__}:{str(exc)[:120]}"
    result["latency_ms"] = int((time.monotonic() - started) * 1000)
    return result


__all__ = [
    "DEFAULT_BASE_URL",
    "DEFAULT_MODEL",
    "legacy_config",
    "parse_providers",
    "provider_pool",
    "ordered_pool",
    "active_provider_file",
    "get_active_provider_name",
    "set_active_provider",
    "messages_payload",
    "complete",
    "complete_messages",
    "probe_provider",
]
