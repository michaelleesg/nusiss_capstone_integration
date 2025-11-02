#!/usr/bin/env bash
# heva_prune_duplicates.sh
# WSL-safe (no set -euo). Keeps the LAST definition of certain HEVA targets and
# removes earlier duplicates. Backs up to Makefile.bak.heva_prune.
#
# Usage (from repo root):
#   chmod +x heva_prune_duplicates.sh
#   ./heva_prune_duplicates.sh
#
# Targets deduped:
#   - qdr-seed
#   - qdr-wipe-docs
#   - qdr-wipe-heva_v1

MAKEFILE="Makefile"

if [ ! -f "$MAKEFILE" ]; then
  echo "❌ $MAKEFILE not found in $(pwd)"
  read -rp "Press Enter to exit..."
  exit 0
fi

cp -f "$MAKEFILE" "${MAKEFILE}.bak.heva_prune" 2>/dev/null || true

awk '
  BEGIN {
    targets[0] = "qdr-seed"
    targets[1] = "qdr-wipe-docs"
    targets[2] = "qdr-wipe-heva_v1"
    for (i in targets) want[targets[i]] = 1
  }
  {
    line[NR] = $0
    # capture header lines like: qdr-seed: or qdr-seed : deps
    if (match($0, /^([A-Za-z0-9_.-]+)[[:space:]]*:/, m)) {
      name = m[1]
      if (name in want) {
        # remember the last occurrence (overwrite while scanning)
        last[name] = NR
      }
    }
    n = NR
  }
  END {
    # second pass: print while skipping earlier duplicate blocks
    skip = 0
    for (i=1; i<=n; i++) {
      L = line[i]

      # Detect a new target header (start of a block)
      header = 0
      name = ""
      if (match(L, /^([A-Za-z0-9_.-]+)[[:space:]]*:/, m)) {
        header = 1
        name = m[1]
      }

      # If currently skipping, stop skipping when we reach ANY new target header
      if (skip) {
        if (header) {
          skip = 0
        } else {
          # keep skipping recipe lines/comments of the earlier duplicate
          continue
        }
      }

      # If this is a header for one of our targets AND it is NOT the last occurrence, skip its block
      if (header && (name in want) && (i != last[name])) {
        skip = 1
        # do not print this header or its recipe; continue to next line
        continue
      }

      # Otherwise, print the line
      print L
    }
  }
' "${MAKEFILE}.bak.heva_prune" > "${MAKEFILE}.tmp"

mv "${MAKEFILE}.tmp" "${MAKEFILE}"

echo "OK: Pruned earlier duplicates for qdr-seed/qdr-wipe-docs/qdr-wipe-heva_v1."
echo "Backup at ${MAKEFILE}.bak.heva_prune"
read -rp "Press Enter to close..."
