#!/usr/bin/env bash
# add_heva_quick_help.sh — WSL-safe; idempotent; preserves real TABs in Makefile recipes.
# Inserts/refreshes a compact `make help` section between marker lines.
# Notes:
# - Uses REAL TAB characters in the recipe.
# - Replaces existing block between START/END markers if present.
# - Keeps $(QDR) $(COL) $(TAG) $(DAYS) literals so Make will show defaults at runtime.
# - Consider: \t instead of a real TAB, and Make/Bash mangled $ defaults. We've moved defaults to Make (?=)
#   and call scripts with $(VAR) elsewhere to avoid $ being eaten and $$→PID issues.

set +e

MAKEFILE="Makefile"
START="### >>> HEVA QUICK HELP START >>>"
END="### <<< HEVA QUICK HELP END <<<<"

if [ ! -f "$MAKEFILE" ]; then
  echo "❌ $MAKEFILE not found in $(pwd)"
  exit 1
fi

cp -f "$MAKEFILE" "${MAKEFILE}.bak.heva_quick_help" 2>/dev/null || true

# Strip existing QUICK HELP block (if any)
awk -v s="$START" -v e="$END" '
  BEGIN { skip=0 }
  index($0,s) { skip=1; next }
  index($0,e) { skip=0; next }
  !skip { print }
' "${MAKEFILE}.bak.heva_quick_help" > "${MAKEFILE}.tmp"

# Append fresh block with REAL TABs for recipe lines
{
  printf "%s\n" "$START"
  printf "%s\n" ".PHONY: help"
  printf "%s\n" "help:"
  printf "\t%s\n" '@echo "Targets:"'
  printf "\t%s\n" '@echo "  qdr-since [QDR=… COL=… TAG=… DAYS=…]  – list items since N days"'
  printf "\t%s\n" '@echo "  heva-clean                             – purge Makefile.bak.*, *.tmp, *.log"'
  printf "\t%s\n" '@echo "Vars (Make defaults): QDR=$(QDR)  COL=$(COL)  TAG=$(TAG)  DAYS=$(DAYS)"'
  printf "%s\n" "$END"
} >> "${MAKEFILE}.tmp"

mv -f "${MAKEFILE}.tmp" "$MAKEFILE"

echo "✅ Added HEVA quick help. Backup at ${MAKEFILE}.bak.heva_quick_help"
echo "Sanity:"
echo "  nl -ba Makefile | sed -n '/$START/,\"/$END/\"p'"
echo "  make help"
