#!/usr/bin/env bash
# fix_clock_skew.sh
# WSL-safe helper to reduce 'Clock skew detected' warnings from GNU make.
# - Does NOT use 'set -e' (prevents WSL windows from closing on minor errors).
# - Touches Makefile/*.mk if their mtime is slightly in the future relative to now.
# - Sleeps briefly to let filesystem timestamps settle.
#
# Usage:
#   bash fix_clock_skew.sh          # just normalize times
#   bash fix_clock_skew.sh --run    # normalize then run `make qdr-smoke`
#
# Note: This only adjusts Make-related files; it won't modify your tracked sources.

set +e

# Prefer GNU stat format, fallback to BSD (macOS) if needed
stat_mtime() {
  local f="$1"
  if stat -c %Y "$f" >/dev/null 2>&1; then
    stat -c %Y "$f"
  else
    stat -f %m "$f"
  fi
}

now="$(date +%s)"
touched=0
files=(Makefile *.mk)
for f in "${files[@]}"; do
  [ -e "$f" ] || continue
  m="$(stat_mtime "$f")"
  if [ -n "$m" ] && [ "$m" -gt "$now" ] 2>/dev/null; then
    touch "$f"
    touched=$((touched+1))
  fi
done

# Even if nothing was in the future, a tiny sleep helps FS settle on WSL mounts.
sleep 1

echo "✅ Clock skew helper finished (touched $touched file(s))."
if [ "${1:-}" = "--run" ]; then
  echo "→ Running: make qdr-smoke"
  make qdr-smoke || true
fi

# Always end interactively in WSL to avoid closing the window on exit
read -rp "Press Enter to close..."
