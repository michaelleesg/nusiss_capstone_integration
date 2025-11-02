#!/usr/bin/env bash
# qdr_all.sh
# WSL-safe: no 'set -euo pipefail'; ends with a prompt.
# Runs clock-fix → optional seed → smoke suite.

QDR="${QDR:-http://127.0.0.1:6333}"

echo "→ make qdr-fix-clock"
make qdr-fix-clock QDR="$QDR" || echo "[warn] qdr-fix-clock failed"

# If you want to ensure at least one demo doc exists:
if [ "${HEVA_SEED_ON_RUN:-1}" = "1" ]; then
  echo
  echo "→ make qdr-seed (idempotent)"
  make qdr-seed QDR="$QDR" || echo "[warn] qdr-seed failed (continuing)"
fi

echo
echo "→ make qdr-smoke"
make qdr-smoke QDR="$QDR" || echo "[warn] qdr-smoke failed"

read -rp "Done. Press Enter to close..."
