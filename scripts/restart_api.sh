#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PORT="${PORT:-8000}"
APP="api.search_api_rich:app"

kill_by_port() {
  local port="$1"
  echo "🔎 Stopping any process on :$port…"

  if command -v lsof >/dev/null 2>&1; then
    # Kill all PIDs listening on the port (each on its own line)
    lsof -t -i :"$port" 2>/dev/null | xargs -r kill -9 || true
  elif command -v ss >/dev/null 2>&1; then
    # Fallback via ss + awk to extract PIDs
    ss -lntp "sport = :$port" 2>/dev/null \
      | awk -F'[=,]' '/pid=/ {print $2}' \
      | xargs -r kill -9 || true
  else
    # Last resort: pattern kill (may overkill if multiple uvicorns)
    pkill -f "uvicorn .*${APP}" || true
  fi
}

load_env() {
  # Load .env safely (supports KEY=VALUE without exports)
  if [[ -f .env ]]; then
    echo "📦 Loading environment from .env"
    set -o allexport
    # shellcheck source=/dev/null
    source .env
    set +o allexport
  fi
}

kill_by_port "$PORT"
load_env

echo "🚀 Starting uvicorn on 0.0.0.0:$PORT…"
exec uvicorn "$APP" --host 0.0.0.0 --port "$PORT" --reload

