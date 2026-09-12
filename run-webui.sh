#!/usr/bin/env bash
# SurfaceForge WebUI launcher — Linux / macOS
# Auto-loads .env, resolves Python 3.10+, starts the WebUI server.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# --- .env loading (values already set in env win) ---
if [[ -f .env ]]; then
  while IFS='=' read -r key value; do
    # Skip comments and blank lines
    [[ -z "$key" || "$key" =~ ^# ]] && continue
    key="$(echo "$key" | xargs)"
    # Strip surrounding quotes
    value="${value%\"}"; value="${value#\"}"
    value="${value%\'}"; value="${value#\'}"
    if [[ -z "${!key:-}" ]]; then
      export "$key=$value"
    fi
  done < .env
fi

# --- Python resolution (3.10+) ---
PY=""
for candidate in "${PA_PYTHON:-}" python3.12 python3.11 python3.10 python3 python; do
  [[ -z "$candidate" ]] && continue
  if command -v "$candidate" >/dev/null 2>&1; then
    if "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)' 2>/dev/null; then
      PY="$candidate"
      break
    fi
  fi
done
if [[ -z "$PY" ]]; then
  echo "ERROR: Python 3.10+ not found. Install Python or set PA_PYTHON." >&2
  exit 1
fi

# --- Required secrets (fall back to .env values) ---
: "${WEBUI_ADMIN_PASSWORD:?WEBUI_ADMIN_PASSWORD required (>=16 chars). Set in .env or export.}"
: "${WEBUI_SESSION_SECRET:?WEBUI_SESSION_SECRET required (>=32 chars). Set in .env or export.}"

export PYTHONUTF8=1
export PYTHONIOENCODING=utf-8

PORT="${WEBUI_PORT:-8088}"
STATE_DIR="${WEBUI_STATE_DIR:-$SCRIPT_DIR/webui-state}"

exec "$PY" -m webui.server \
  --state-dir "$STATE_DIR" \
  --static-dir "$SCRIPT_DIR/webui/dist" \
  --port "$PORT"
