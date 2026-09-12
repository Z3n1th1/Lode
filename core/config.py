"""Load .env config file into os.environ on import.

Usage: just ``import core.config`` at the top of any entry point.
Values already set in the environment are NOT overwritten (env wins over file).
"""
from __future__ import annotations

import os
from pathlib import Path


def load_dotenv(path: str | Path | None = None) -> int:
    """Read a .env file and set missing env vars. Returns count of vars set."""
    if path is None:
        # Walk up from this file to find .env
        candidates = [
            Path(__file__).resolve().parents[1] / ".env",  # project root
            Path.cwd() / ".env",
        ]
    else:
        candidates = [Path(path)]

    count = 0
    for candidate in candidates:
        if not candidate.is_file():
            continue
        for line in candidate.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if not key or key.startswith("#"):
                continue
            # Strip optional quotes
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                value = value[1:-1]
            # Don't overwrite existing env vars
            if key not in os.environ or not os.environ[key].strip():
                os.environ[key] = value
                count += 1
        break  # Only load the first found .env
    return count


# Auto-load on import
_loaded = load_dotenv()
