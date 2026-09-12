"""Thin WebUI adapter for the independent :mod:`intel` source registry."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from intel.registry import add_source as _add_source
from intel.registry import load_sources as _load_sources
from intel.registry import remove_source as _remove_source
from intel.registry import record_status as _record_status
from intel.registry import set_enabled as _set_enabled


def load_sources(state_dir: str | Path | None = None) -> list[dict[str, Any]]:
    return _load_sources(state_dir)


def add_source(payload: Mapping[str, Any], state_dir: str | Path | None = None) -> tuple[bool, str]:
    return _add_source(payload, state_dir)


def set_enabled(source_id: str, enabled: bool, state_dir: str | Path | None = None) -> bool:
    return _set_enabled(source_id, enabled, state_dir)


def remove_source(source_id: str, state_dir: str | Path | None = None) -> bool:
    return _remove_source(source_id, state_dir)


def record_status(source_id: str, status: str, *, item_count: int = 0, error: str = "", state_dir: str | Path | None = None) -> bool:
    return _record_status(source_id, status, item_count=item_count, error=error, value=state_dir)
