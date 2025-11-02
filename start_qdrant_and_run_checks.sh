#!/usr/bin/env bash
# WSL‑safe launcher for Qdrant + HEVA Makefile checks
# - Avoids `set -e` so the window won't close on first error.
# - Adds a final pause so WSL terminals set to "close on exit" don't vanish.
# - Prints clear diagnostics throughout.

set -u  # keep 'nounset', but NOT '-e'; we handle errors manually
# Do NOT use: set -e

QDR_DEFAULT="http://127.0.0.1:6333"
QDR="${QDR:-$QDR_DEFAULT}"
CONTAINER_NAME="${CONTAINER_NAME:-qdrant}"
IMAGE="${IMAGE:-qdrant/qdrant:latest}"
VOL="${VOL:-qdrant_data}"
CURL="${CURL:-curl -sS}"

say() { printf "\n—— %s\n" "$*"; }
warn() { printf "\n[WARN] %s\n" "$*" >&2; }
die() { printf "\n[ERROR] %s\n" "$*" >&2; read -rp "Press Enter to close this window..."; exit 1; }

run_safe() {
  # Run a command but don't kill the shell on failure; show exit code.
  # Usage: run_safe <label> -- <cmd> [args...]
  local label="$1"; shift
  if [[ "$1" == "--" ]]; then shift; fi
  say "$label"
  "$@"
  local rc=$?
  if (( rc != 0 )); then
    warn "Command failed (exit $rc): $*"
  fi
  return $rc
}

# 0) Sanity: docker available?
if ! command -v docker >/dev/null 2>&1; then
  die "Docker is not installed or not on PATH."
fi

# 1) Ensure Qdrant container is running
say "Ensuring Qdrant container '$CONTAINER_NAME' is running..."
if docker ps --format '{{.Names}}' | grep -qw "$CONTAINER_NAME"; then
  if [[ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER_NAME" 2>/dev/null)" != "true" ]]; then
    run_safe "Starting existing container..." -- docker start "$CONTAINER_NAME" >/dev/null || {
      warn "Failed to start existing container, removing and recreating..."
      docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    }
  fi
elif docker ps -a --format '{{.Names}}' | grep -qw "$CONTAINER_NAME"; then
  run_safe "Starting existing container..." -- docker start "$CONTAINER_NAME" >/dev/null || {
    warn "Failed to start existing container, removing and recreating..."
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  }
fi

if ! docker ps --format '{{.Names}}' | grep -qw "$CONTAINER_NAME"; then
  say "Launching fresh Qdrant container..."
  run_safe "docker run $IMAGE" -- docker run -d --name "$CONTAINER_NAME"         -p 6333:6333 -p 6334:6334         -v "$VOL":/qdrant/storage         "$IMAGE" >/dev/null || die "Could not start Qdrant container."
fi

# 2) Wait for /readyz
say "Waiting for Qdrant to become ready at $QDR ..."
ready=0
for i in $(seq 1 20); do
  if $CURL --max-time 2 "$QDR/readyz" >/dev/null 2>&1; then
    ready=1; break
  fi
  sleep 1
done
(( ready == 1 )) || die "Qdrant did not become ready at $QDR (timeout)."
say "Qdrant is ready."

# 3) Optional seed script
if [[ -x "./seed_qdrant_demo.sh" ]]; then
  # WSL‑safe: don't crash if seeding fails
  run_safe "Seeding demo data (./seed_qdrant_demo.sh)..." -- ./seed_qdrant_demo.sh || true
else
  say "./seed_qdrant_demo.sh not found; skipping demo seed."
fi

# 4) Run Makefile helpers with explicit QDR
if [[ -f Makefile ]]; then
  run_safe "make qdr-count-oct (QDR=${QDR})" -- make QDR="$QDR" qdr-count-oct || true
  run_safe "make qdr-last7 (QDR=${QDR})"     -- make QDR="$QDR" qdr-last7     || true
  run_safe "make qdr-ta-since (QDR=${QDR})"  -- make QDR="$QDR" qdr-ta-since  || true
else
  warn "No Makefile found in: $(pwd)"
fi

say "Done."
# Final guard so WSL terminals set to “close on exit” won’t disappear
read -rp "Press Enter to close this window..."
