"""Shared router context."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from console.projections import ReadOnlyControlPlane


@dataclass
class Ctx:
    """Everything a router needs, passed explicitly instead of via closure."""

    state_dir: Path
    control_plane: ReadOnlyControlPlane
    password: str
    session_secret: str
    static_dir: Optional[Path] = None


# Re-exported here so every router can `from console.routers.base import _NOSTORE`.
_NOSTORE = {"Cache-Control": "no-store"}

__all__ = ["Ctx", "_NOSTORE"]
