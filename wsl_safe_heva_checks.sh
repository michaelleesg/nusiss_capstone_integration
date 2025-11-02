#!/usr/bin/env bash
# WSL-safe HEVA/Qdrant runner
# - No `set -e` (to avoid closing the window on errors)
# - Each step is guarded; failures are logged but do not exit the shell
# - Ends with a prompt so Windows Terminal won't auto-close
set -uo pipefail

# If you prefer strict mode with a gentle error handler, uncomment:
# set -Eeuo pipefail
# trap 'ec=$?; echo "⚠️ Script hit an error (exit=$ec) but will keep the window open."; read -rp "Press Enter to finish..."; exit $ec' ERR

run() {
  echo "→ $*"
  "$@"
  ec=$?
  if [ $ec -ne 0 ]; then
    echo "⚠️  Command failed (exit=$ec): $*"
  fi
  return 0
}

# Optional: seed demo data if the script exists
if [ -f "./seed_qdrant_demo.sh" ]; then
  run bash ./seed_qdrant_demo.sh
else
  echo "ℹ️  ./seed_qdrant_demo.sh not found; skipping demo seed."
fi

# Helpers (run even if the previous step failed)
run make qdr-count-oct
run make qdr-last7
run make qdr-ta-since

echo ""
echo "✅ Done. (WSL-safe runner finished.)"
read -rp "Press Enter to close this window..."
