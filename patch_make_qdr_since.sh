#!/usr/bin/env bash
# patch_make_qdr_since.sh
# WSL-safe (no set -euo). Adds a qdr-since target that shells out to scripts/qdr_since.sh.
# Ensures (1) real TAB in recipe, (2) avoids fragile inline jq in Makefile.

MAKEFILE="Makefile"
START_MARK="### >>> HEVA PARAM START >>>"
END_MARK="### <<< HEVA PARAM END <<<"

[ -f "$MAKEFILE" ] || { echo "❌ $MAKEFILE not found in $(pwd)"; exit 1; }

# Ensure scripts directory exists
mkdir -p scripts

# If qdr_since.sh exists alongside, move it into scripts/
if [ -f "qdr_since.sh" ] && [ ! -f "scripts/qdr_since.sh" ]; then
  mv -f qdr_since.sh scripts/qdr_since.sh
fi

# If a previous copy is already in scripts/, keep it
if [ ! -f "scripts/qdr_since.sh" ]; then
  echo "⚠️  scripts/qdr_since.sh not found. Copy it into your repo's scripts/ dir."
fi

cp -f "$MAKEFILE" "${MAKEFILE}.bak.qdr_since_install" 2>/dev/null || true

# Remove prior block
awk -v s="$START_MARK" -v e="$END_MARK" '
  BEGIN{skip=0}
  index($0,s){skip=1; next}
  index($0,e){skip=0; next}
  !skip{print}
' "${MAKEFILE}.bak.qdr_since_install" > "${MAKEFILE}.tmp"

# Append a minimal, robust target that just calls the script.
{
  printf "### >>> HEVA PARAM START >>>\n"
  printf ".PHONY: qdr-since\n"
  printf "qdr-since:\n"
  printf "\t@bash scripts/qdr_since.sh \"$$\{QDR:-http://127.0.0.1:6333\}\" \"$$\{COL:-heva_docs\}\" \"$$\{TAG:-THREAT_ACTOR\}\" \"$$\{DAYS:-7\}\"\n"
  printf "### <<< HEVA PARAM END <<<\n"
} >> "${MAKEFILE}.tmp"

mv "${MAKEFILE}.tmp" "${MAKEFILE}"
echo "✅ Added qdr-since (script-backed). Backup at ${MAKEFILE}.bak.qdr_since_install"
echo "Run examples:"
echo "  make qdr-since"
echo '  make qdr-since DAYS=30'
echo '  make qdr-since TAG="INDICATOR"'
echo '  make qdr-since COL=heva_docs QDR=http://127.0.0.1:6333'
