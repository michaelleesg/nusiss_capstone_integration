#!/usr/bin/env bash
# fix_make_qdr_since_call.sh
# WSL-safe (no set -euo); idempotent. Converts TAB@@ placeholders to real tabs.
# Ensures qdr-since calls scripts/qdr_since.sh with clean, shell-defaulted args.

MAKEFILE="Makefile"
START_MARK="### >>> HEVA PARAM START >>>"
END_MARK="### <<< HEVA PARAM END <<<"

[ -f "$MAKEFILE" ] || { echo "❌ $MAKEFILE not found in $(pwd)"; exit 1; }

# Heads-up only (non-fatal)
for dep in awk sed; do
  command -v "$dep" >/dev/null 2>&1 || echo "⚠️  Missing dependency: $dep"
done

cp -f "$MAKEFILE" "${MAKEFILE}.bak.qdr_since_clean" 2>/dev/null || true

# Strip the old PARAM block (if any)
awk -v s="$START_MARK" -v e="$END_MARK" '
  BEGIN{skip=0}
  index($0,s){skip=1; next}
  index($0,e){skip=0; next}
  !skip{print}
' "${MAKEFILE}.bak.qdr_since_clean" > "${MAKEFILE}.tmp"

# Append a fresh, minimal, robust block.
# NOTE: All recipe lines below start with a REAL TAB character.
{
  printf "%s\n" "### >>> HEVA PARAM START >>>"
  printf "%s\n" ".PHONY: qdr-since"
  printf "%s\n" "qdr-since:"
  printf "\t%s\n" 'bash -lc '\''QDR="${QDR:-http://127.0.0.1:6333}"; COL="${COL:-heva_docs}"; TAG="${TAG:-THREAT_ACTOR}"; DAYS="${DAYS:-7}"; exec bash scripts/qdr_since.sh "$QDR" "$COL" "$TAG" "$DAYS"'\'
  printf "%s\n" "### <<< HEVA PARAM END <<<"
} >> "${MAKEFILE}.tmp"

# Replace TAB@@ placeholders anywhere in Makefile with real tabs at recipe starts.
# (just-in-case safety net)
sed -E 's/^TAB@@/\t/' "${MAKEFILE}.tmp" > "${MAKEFILE}.fixed"

mv -f "${MAKEFILE}.fixed" "${MAKEFILE}"
rm -f "${MAKEFILE}.tmp" 2>/dev/null || true

echo "✅ Repaired qdr-since target. Backup at ${MAKEFILE}.bak.qdr_since_clean"
echo "Run: make qdr-since | make qdr-since DAYS=30 | make qdr-since TAG=INDICATOR"
echo "Note: WSL-safe; avoids window-closing patterns; preserves real tabs; guards jq quoting."

