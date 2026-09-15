"""Conversation modes: presets that bundle a skill pack, a model tier, an
autonomy level and a tool set for one turn.

Loaded from ``config/modes.yaml`` (PyYAML) with a hard-coded fallback so the
Console still works if the file is missing. ``Mode.skill`` names a
:mod:`core.skills` pack whose dispatcher primes the turn's system prompt.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

MODES_PATH = Path(__file__).resolve().parents[1] / "config" / "modes.yaml"

DEFAULT_MODE = "chat"

_FALLBACK: Dict[str, Dict[str, Any]] = {
    "chat": {"title": "对话", "skill": "chat", "tier": "explorer", "autonomy": "none",
             "tools": [], "system_fragment": "纯对话模式：只讨论与推理，不主动发起任何扫描或请求。"},
    "pentest": {"title": "挖洞", "skill": "pentest", "tier": "reasoner", "autonomy": "ask",
                "tools": ["scan_target", "run_agent_analysis", "fetch_url", "show_blackboard",
                          "add_candidates", "show_progress", "auto_scan"],
                "system_fragment": "挖洞模式：黑盒 SRC 与授权渗透同一套打法，"
                                   "只在授权范围内动手，先侦察再逐点验证，写操作先要人工确认。"},
}

AUTONOMY_LEVELS = ("none", "ask", "auto")


@dataclass(frozen=True)
class Mode:
    name: str
    title: str
    skill: str
    tier: str = "reasoner"
    autonomy: str = "ask"
    tools: Tuple[str, ...] = field(default_factory=tuple)
    system_fragment: str = ""

    @property
    def may_escalate(self) -> bool:
        """``none`` modes never auto-launch a subtask."""
        return self.autonomy in ("ask", "auto")

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "title": self.title, "skill": self.skill,
                "tier": self.tier, "autonomy": self.autonomy, "tools": list(self.tools)}


def _coerce(name: str, raw: Dict[str, Any]) -> Mode:
    autonomy = str(raw.get("autonomy") or "ask").strip()
    if autonomy not in AUTONOMY_LEVELS:
        autonomy = "ask"
    tools = raw.get("tools") or []
    return Mode(
        name=name,
        title=str(raw.get("title") or name),
        skill=str(raw.get("skill") or name),
        tier=str(raw.get("tier") or "reasoner"),
        autonomy=autonomy,
        tools=tuple(str(t) for t in tools),
        system_fragment=str(raw.get("system_fragment") or ""),
    )


def load_modes(path: Path | str = MODES_PATH) -> Dict[str, Mode]:
    """Modes from the YAML file, falling back to the built-in presets."""
    raw: Dict[str, Any] = {}
    try:
        import yaml  # type: ignore

        doc = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        if isinstance(doc, dict) and isinstance(doc.get("modes"), dict):
            raw = {str(k): v for k, v in doc["modes"].items() if isinstance(v, dict)}
    except Exception:  # noqa: BLE001 - missing/broken YAML -> fallback
        raw = {}
    if not raw:
        raw = dict(_FALLBACK)
    return {name: _coerce(name, body) for name, body in raw.items()}


_MODES: Dict[str, Mode] = {}


def modes() -> Dict[str, Mode]:
    global _MODES
    if not _MODES:
        _MODES = load_modes()
    return _MODES


def get_mode(name: str) -> Mode:
    """A mode by name (unknown names fall back to the default mode)."""
    table = modes()
    key = str(name or "").strip() or DEFAULT_MODE
    if key in table:
        return table[key]
    return table.get(DEFAULT_MODE) or _coerce(DEFAULT_MODE, _FALLBACK[DEFAULT_MODE])


def list_modes() -> List[Dict[str, Any]]:
    return [m.to_dict() for m in modes().values()]


__all__ = ["Mode", "DEFAULT_MODE", "AUTONOMY_LEVELS", "load_modes", "modes",
           "get_mode", "list_modes", "MODES_PATH"]
