#!/usr/bin/env bash
# fix_qdr_since_tabs_vars.sh
# - WSL-safe (no set -euo)
# - Replaces the HEVA PARAM block with a clean one
# - Uses a REAL TAB at the recipe start
# - Doubles $ -> $$ so the shell receives variables
# - Calls scripts/qdr_since.sh to avoid single-quoted jq EOF issues

MAKEFILE="Makefile"
START_MARK="### >>> HEVA PARAM START >>>"
END_MARK="### <<< HEVA PARAM END <<<"

if [ ! -f "$MAKEFILE" ]; then
  echo "❌ $MAKEFILE not found in $(pwd)"
  exit 1
fi

cp -f "$MAKEFILE" "${MAKEFILE}.bak.qdr_since_tabs_vars" 2>/dev/null || true

# Strip existing HEVA PARAM block (if any)
awk -v s="$START_MARK" -v e="$END_MARK" '
  BEGIN { skip=0 }
  index($0,s) { skip=1; next }
  index($0,e) { skip=0; next }
  !skip { print }
' "${MAKEFILE}.bak.qdr_since_tabs_vars" > "${MAKEFILE}.tmp"

# Append fresh, correct block (printf ensures a REAL TAB on the recipe line).
{
  printf "### >>> HEVA PARAM START >>>\n"
  printf ".PHONY: qdr-since\n"
  printf "qdr-since:\n"
  printf "\t@bash -lc 'QDR=\"$${QDR:-http://127.0.0.1:6333}\"; COL=\"$${COL:-heva_docs}\"; TAG=\"$${TAG:-THREAT_ACTOR}\"; DAYS=\"$${DAYS:-7}\"; exec bash scripts/qdr_since.sh \"$${QDR}\" \"$${COL}\" \"$${TAG}\" \"$${DAYS}\"'\n"
  printf "### <<< HEVA PARAM END <<<\n"
} >> "${MAKEFILE}.tmp"

mv "${MAKEFILE}.tmp" "${MAKEFILE}"

echo "✅ Rewrote qdr-since with REAL TAB + $$ vars. Backup at ${MAKEFILE}.bak.qdr_since_tabs_vars"
echo "Run:"
echo "  make -n qdr-since       # dry-run to verify the tabbed recipe"
echo "  make qdr-since           # defaults: DAYS=7 TAG=THREAT_ACTOR COL=heva_docs"
echo "  make qdr-since DAYS=30"
echo "  make qdr-since TAG=INDICATOR"
echo "  make qdr-since COL=heva_docs QDR=http://127.0.0.1:6333"
