#!/usr/bin/env bash
# Boot the local range, run the Lode hunt against it, tear the range down.
#
#   bash ranges/lode-range/run.sh [cycles] [max_requests]
#
# The Console refuses 127.0.0.1 by design (core/targets.py:84), so this goes
# through the CLI, whose per-request gate (SurfaceScope.check_url) admits an IP
# listed in allowed_ips and still rejects everything out of scope.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PY="${PA_PYTHON:-D:/Environment/Python/miniforge/envs/py310/python.exe}"
PORT=8791
CYCLES="${1:-12}"
MAX_REQUESTS="${2:-60}"
OUT="$ROOT/out/lode-range"

cd "$ROOT"
mkdir -p "$OUT"

"$PY" ranges/lode-range/app.py --port "$PORT" >"$OUT/range-server.log" 2>&1 &
RANGE_PID=$!
cleanup() { kill "$RANGE_PID" 2>/dev/null || true; }
trap cleanup EXIT

# Wait for readiness rather than sleeping a fixed amount.
for _ in $(seq 1 40); do
  if curl -sf "http://127.0.0.1:$PORT/robots.txt" >/dev/null 2>&1; then break; fi
  sleep 0.25
done
curl -sf "http://127.0.0.1:$PORT/robots.txt" >/dev/null || { echo "range did not come up"; exit 1; }
echo "[run] range up on http://127.0.0.1:$PORT/"

set +e
"$PY" lode.py auto \
  --scope ranges/lode-range/scope-lode-range.json \
  --from-scope \
  --out-dir "$OUT" \
  --max-cycles "$CYCLES" \
  --max-requests "$MAX_REQUESTS"
RC=$?
set -e

echo "[run] lode exit=$RC  artifacts in $OUT"
echo "[run] compare findings against ranges/lode-range/GROUND_TRUTH.md"
