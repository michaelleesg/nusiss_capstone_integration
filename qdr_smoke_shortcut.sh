#!/usr/bin/env bash
# qdr_smoke_shortcut.sh
# WSL-safe: no 'set -euo pipefail'; ends with a prompt.
# Runs clock-fix then the full smoke suite.

echo "→ make qdr-fix-clock"
make qdr-fix-clock QDR="${QDR:-http://127.0.0.1:6333}" || echo "[warn] qdr-fix-clock failed"

echo
echo "→ make qdr-smoke"
make qdr-smoke QDR="${QDR:-http://127.0.0.1:6333}" || echo "[warn] qdr-smoke failed"

read -rp "Done. Press Enter to close..."
