"""Which tools a turn may call: a mode's declared names resolved to schemas + impls.

A mode declares tool *names* (``core/modes.py``, ``config/modes.yaml``). This module
turns those names into the pair :func:`core.llm_client.run_tool_loop` needs — the
OpenAI function schemas and a ``name -> callable`` dispatch table.

A tool is available **iff it has both a schema and an implementation**; that is
structural here (``_register`` only records such pairs), so a name declared in the
mode table but never implemented is simply reported as missing rather than turning
into a tool the model can call and the runtime cannot serve.

Lives in ``agents/`` rather than ``core/`` because it imports the tool providers:
``core/`` is the lower layer that ``agents/`` depends on, and putting it there would
invert that.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Sequence, Tuple

ToolImpl = Callable[[Any, Dict[str, Any]], str]   # (session, args) -> JSON string

_SCHEMAS: Dict[str, Dict[str, Any]] = {}
_IMPLS: Dict[str, ToolImpl] = {}
_LOADED = False


def _register(schemas: Sequence[Dict[str, Any]], impls: Dict[str, ToolImpl]) -> None:
    for schema in schemas:
        function = schema.get("function") or {}
        name = str(function.get("name") or "")
        impl = impls.get(name)
        if name and impl is not None:
            _SCHEMAS[name] = schema
            _IMPLS[name] = impl


def _load() -> None:
    """Import the tool providers once, lazily.

    Deferred (and flagged before importing) so importing this module is free of
    cycles with the providers, which import it back through the turn handler.
    """
    global _LOADED
    if _LOADED:
        return
    _LOADED = True
    from agents import src_chat

    _register(src_chat.SRC_TOOLS, src_chat._TOOL_DISPATCH)


def resolve(names: Sequence[str]) -> Tuple[List[Dict[str, Any]], Dict[str, ToolImpl], List[str]]:
    """``(schemas, dispatch, missing)`` for the declared tool names.

    Order follows ``names``; duplicates are collapsed. A name without both a schema
    and an implementation is reported in ``missing`` and omitted from both returned
    collections — the turn still runs, just without that tool.
    """
    _load()
    schemas: List[Dict[str, Any]] = []
    dispatch: Dict[str, ToolImpl] = {}
    missing: List[str] = []
    for raw in names or ():
        name = str(raw or "").strip()
        if not name or name in dispatch or name in missing:
            continue
        schema = _SCHEMAS.get(name)
        impl = _IMPLS.get(name)
        if schema is None or impl is None:
            missing.append(name)
            continue
        schemas.append(schema)
        dispatch[name] = impl
    return schemas, dispatch, missing


def available() -> List[str]:
    """Every implemented tool name (diagnostics and tests)."""
    _load()
    return sorted(_SCHEMAS)


__all__ = ["ToolImpl", "resolve", "available"]
