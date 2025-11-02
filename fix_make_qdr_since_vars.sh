#!/usr/bin/env bash
# fix_make_qdr_since_vars.sh
# WSL-safe (no set -euo); idempotent; preserves real TABs.
# Fixes the qdr-since recipe to use $$ so Bash receives literal $ vars.

MAKEFILE="Makefile"
START_MARK="### >>> HEVA PARAM START >>>"
END_MARK="### <<< HEVA PARAM END <<<"

if [ ! -f "$MAKEFILE" ]; then
  echo "❌ $MAKEFILE not found in $(pwd)"
  exit 1
fi

cp -f "$MAKEFILE" "${MAKEFILE}.bak.qdr_since_vars" 2>/dev/null || true

# Remove any existing HEVA PARAM block entirely
awk -v s="$START_MARK" -v e="$END_MARK" '
  BEGIN{skip=0}
  index($0,s){skip=1; next}
  index($0,e){skip=0; next}
  !skip{print}
' "${MAKEFILE}.bak.qdr_since_vars" > "${MAKEFILE}.tmp"

# Append fresh block (recipe lines begin with a REAL TAB; all $ are doubled to $$)
cat >> "${MAKEFILE}.tmp" <<'MAKE'
### >>> HEVA PARAM START >>>
.PHONY: qdr-since
qdr-since:
\t@bash -lc 'QDR="$${QDR:-http://127.0.0.1:6333}"; COL="$${COL:-heva_docs}"; TAG="$${TAG:-THREAT_ACTOR}"; DAYS="$${DAYS:-7}"; exec bash scripts/qdr_since.sh "$${QDR}" "$${COL}" "$${TAG}" "$${DAYS}"'
### <<< HEVA PARAM END <<<
MAKE

mv "${MAKEFILE}.tmp" "${MAKEFILE}"
echo "✅ Rewrote qdr-since with $$ vars. Backup at ${MAKEFILE}.bak.qdr_since_vars"
echo "Try: make qdr-since  |  make qdr-since DAYS=30  |  make qdr-since TAG=INDICATOR"
