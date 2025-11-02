#!/usr/bin/env bash
# repair_qdr_since_v3.sh
# WSL-safe (no set -euo); idempotent; preserves tabs in Makefile recipes.
# Fixes/installs a robust qdr-since target that won't break quoting.
# Also takes care to (1) write real TABs into Makefile recipes (no TAB@@ placeholders),
# and (2) keep the single-quoted jq program intact to avoid "unexpected EOF" issues.

MAKEFILE="Makefile"
START_MARK="### >>> HEVA PARAM START >>>"
END_MARK="### <<< HEVA PARAM END <<<"

if [ ! -f "$MAKEFILE" ]; then
  echo "❌ $MAKEFILE not found in $(pwd)"
  exit 1
fi

cp -f "$MAKEFILE" "${MAKEFILE}.bak.qdr_since_v3" 2>/dev/null || true

# Remove any existing HEVA PARAM block
awk -v s="$START_MARK" -v e="$END_MARK" '
  BEGIN{skip=0}
  index($0,s){skip=1; next}
  index($0,e){skip=0; next}
  !skip{print}
' "${MAKEFILE}.bak.qdr_since_v3" > "${MAKEFILE}.tmp"

# Append fresh block using printf to ensure real TABs in recipes
{
  printf "### >>> HEVA PARAM START >>>\n"
  printf ".PHONY: qdr-since\n"
  printf "qdr-since:\n"
  printf "\t@DAYS=$${DAYS:-7}; TAG=$${TAG:-THREAT_ACTOR}; COL=$${COL:-heva_docs}; SINCE=$$(( $$(date +%%s) - $$DAYS*86400 )); \\\n"
  printf "\t  echo \"Query: collection=$$COL tag=$$TAG since=$$SINCE ($$DAYS d)\"; \\\n"
  printf "\t  jq -n --arg tag \"$$TAG\" --argjson since $$SINCE '{limit:200, with_payload:true, with_vectors:false, filter:{must:[{key:\"tags\", match:{value:$$tag}}, {key:\"ingested_at_ts\", range:{gte:$$since}}]}}' | \\\n"
  printf "\t  curl -sS -X POST \"$$(printf \"%%s/collections/%%s/points/scroll\" \"$$\{QDR:-http://127.0.0.1:6333\}\" \"$$COL\")\" -H 'Content-Type: application/json' -d @- | \\\n"
  printf "\t  jq -c '{count: ((.result.points // [])|length), items: ((.result.points // [])|map({id, payload}))}'\n"
  printf "### <<< HEVA PARAM END <<<\n"
} >> "${MAKEFILE}.tmp"

mv "${MAKEFILE}.tmp" "${MAKEFILE}"
echo "✅ Repaired qdr-since (v3). Backup at ${MAKEFILE}.bak.qdr_since_v3"
echo "Try:"
echo "  make qdr-since                 # defaults: DAYS=7 TAG=THREAT_ACTOR COL=heva_docs"
echo "  make qdr-since DAYS=30"
echo "  make qdr-since TAG=\"INDICATOR\""
echo "  make qdr-since COL=heva_docs QDR=http://127.0.0.1:6333"
