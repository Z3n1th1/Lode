#!/usr/bin/env bash
# Lode SRC Agent launcher — Linux / macOS
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ -f .env ]]; then
  while IFS='=' read -r key value; do
    [[ -z "$key" || "$key" =~ ^# ]] && continue
    key="$(echo "$key" | xargs)"
    value="${value%\"}"; value="${value#\"}"
    if [[ -z "${!key:-}" ]]; then
      export "$key=$value"
    fi
  done < .env
fi

PY=""
for candidate in "${PA_PYTHON:-}" python3.12 python3.11 python3.10 python3 python; do
  [[ -z "$candidate" ]] && continue
  if command -v "$candidate" >/dev/null 2>&1; then
    if "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)' 2>/dev/null; then
      PY="$candidate"; break
    fi
  fi
done
[[ -z "$PY" ]] && { echo "ERROR: Python 3.10+ not found." >&2; exit 1; }

export PYTHONUTF8=1
export PYTHONIOENCODING=utf-8

exec "$PY" src_agent.py "$@"
