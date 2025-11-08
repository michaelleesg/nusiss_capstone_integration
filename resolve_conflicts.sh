#!/usr/bin/env bash
# resolve_conflicts.sh
# WSL-safe (no 'set -e'). Removes Git conflict markers from listed files,
# keeping either the UPPER ("ours") or LOWER ("theirs") side.
#
# Usage:
#   MODE=lower bash resolve_conflicts.sh <file1> <file2> ...
#   MODE=upper bash resolve_conflicts.sh <file1> <file2> ...
# Default MODE=lower (keep "theirs" block below =======).
#
# Notes:
# - Creates a .bak alongside each file before editing.
# - Processes all conflicts in a file (global).
# - Does not close your WSL window on errors.

MODE="${MODE:-lower}"

if [ $# -lt 1 ]; then
  echo "Usage: MODE={lower|upper} $0 <files...>"
  read -rp "Press Enter to finish..."
  return 0 2>/dev/null || exit 0
fi

for f in "$@"; do
  if [ ! -f "$f" ]; then
    echo "Skip: $f not found"
    continue
  fi

  cp -f "$f" "$f.bak" 2>/dev/null || true

  if [ "$MODE" = "upper" ]; then
    # Keep the UPPER block (ours) between <<<<<<< and =======
    perl -0777 -pe 's/^<<<<<<< .*?\n(.*?)^=======\n(.*?)^>>>>>>> .*?\n/$1/msg' "$f" > "$f.tmp" || true
  else
    # Keep the LOWER block (theirs) between ======= and >>>>>>>
    perl -0777 -pe 's/^<<<<<<< .*?\n(.*?)^=======\n(.*?)^>>>>>>> .*?\n/$2/msg' "$f" > "$f.tmp" || true
  fi

  if [ -s "$f.tmp" ]; then
    mv "$f.tmp" "$f"
    echo "Resolved: $f (mode=$MODE)"
  else
    echo "⚠️  No changes written for $f (check markers or encoding)"
    rm -f "$f.tmp" 2>/dev/null || true
  fi
done

echo ""
echo "Tip: scan again for leftover markers:"
echo "  rg -n '^(<<<<<<<|=======|>>>>>>>)' -S || grep -RnE '^(<<<<<<<|=======|>>>>>>>)' ."
echo ""
read -rp "Press Enter to finish..."
