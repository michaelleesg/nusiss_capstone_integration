#!/usr/bin/env bash
# WSL-safe; idempotent; preserves real TABs; no set -e.
set +e

MAKEFILE="Makefile"
START="### >>> HEVA CLEAN START >>>"
END="### <<< HEVA CLEAN END <<<"

[ -f "$MAKEFILE" ] || { echo "❌ $MAKEFILE not found"; exit 1; }

# 1) Ensure .gitignore has our patterns (including legacy/)
touch .gitignore
for pat in 'legacy/' 'Makefile.bak.*' '*.tmp' '*.log'; do
  grep -qxF "$pat" .gitignore || echo "$pat" >> .gitignore
done

# 2) Remove any prior CLEAN block
cp -f "$MAKEFILE" "${MAKEFILE}.bak.heva_clean_targets" 2>/dev/null || true
awk -v s="$START" -v e="$END" '
  BEGIN{skip=0}
  index($0,s){skip=1; next}
  index($0,e){skip=0; next}
  !skip{print}
' "${MAKEFILE}.bak.heva_clean_targets" > "${MAKEFILE}.tmp"

# 3) Append fresh CLEAN block (NOTE: recipe lines MUST start with a REAL TAB)
{
  printf "%s\n" "$START"
  printf "%s\n" ".PHONY: clean-backups heva-clean"
  printf "%s\n" "clean-backups:"
  printf "\t%s\n" 'rm -f -- Makefile.bak.* *.tmp *.log 2>/dev/null || true'
  printf "%s\n" "heva-clean:"
  printf "\t%s\n" 'find . -maxdepth 1 -type f \( -name '"'"'Makefile.bak.*'"'"' -o -name '"'"'*.tmp'"'"' -o -name '"'"'*.log'"'"' \) -print -delete 2>/dev/null || true'
  printf "\t%s\n" 'echo "✓ HEVA clean done."'
  printf "%s\n" "$END"
} >> "${MAKEFILE}.tmp"

mv -f "${MAKEFILE}.tmp" "$MAKEFILE"
echo "✅ Added heva-clean targets. Backup at ${MAKEFILE}.bak.heva_clean_targets"
echo "Run: make clean-backups | make heva-clean"

