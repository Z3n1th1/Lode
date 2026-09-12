"""Locate and import the reused ai-pentest-matrix scripts (the wrap target).

We do NOT copy those modules — they stay the single source of truth in
``skills/ai-pentest-matrix/scripts``. This bridge finds that directory by walking
upward from here (works in the worktree layout and after a move) or honors an
explicit ``PENTEST_MATRIX_SCRIPTS`` env override, then puts it on sys.path so the
guardrails layer can import policy_engine / created_resources / etc.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional

_REL = Path("skills") / "ai-pentest-matrix" / "scripts"


def find_scripts_dir() -> Optional[Path]:
    override = os.environ.get("PENTEST_MATRIX_SCRIPTS")
    if override:
        p = Path(override).expanduser()
        return p if (p / "policy_engine.py").is_file() else None
    here = Path(__file__).resolve()
    for base in [here.parent, *here.parents]:
        cand = base / _REL
        if (cand / "policy_engine.py").is_file():
            return cand
    return None


_SCRIPTS_DIR = find_scripts_dir()
if _SCRIPTS_DIR is not None and str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))


def scripts_available() -> bool:
    return _SCRIPTS_DIR is not None


def scripts_dir() -> Optional[Path]:
    return _SCRIPTS_DIR
