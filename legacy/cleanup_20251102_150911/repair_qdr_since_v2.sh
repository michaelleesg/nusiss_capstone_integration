#!/usr/bin/env bash
# repair_qdr_since_v2.sh
# WSL-safe (no set -euo); idempotent; preserves tabs in Makefile recipes.
# Fixes/installs a robust qdr-since target that won't break quoting.

MAKEFILE="Makefile"
START_MARK="### >>> HEVA PARAM START >>>"
END_MARK="### <<< HEVA PARAM END <<<"

if [ ! -f "$MAKEFILE" ]; then
  echo "❌ $MAKEFILE not found in $(pwd)"
  exit 1
fi

cp -f "$MAKEFILE" "${MAKEFILE}.bak.qdr_since_v2" 2>/dev/null || true

# Remove any existing HEVA PARAM block
awk -v s="$START_MARK" -v e="$END_MARK" '
  BEGIN{skip=0}
  index($0,s){skip=1; next}
  index($0,e){skip=0; next}
  !skip{print}
' "${MAKEFILE}.bak.qdr_since_v2" > "${MAKEFILE}.tmp"

# Append fresh block using printf to ensure real tabs in recipes
{
  printf "%s\n" "### >>> HEVA PARAM START >>>"
  printf "%s\n" ".PHONY: qdr-since"
  printf "%s\n" "qdr-since:"
  printf "\t%s\n" 'DAYS=$${DAYS:-7}; TAG=$${TAG:-THREAT_ACTOR}; COL=$${COL:-heva_docs}; \'
  printf "\t%s\n" '  SINCE=$$(( $$(date +%s) - $$DAYS*86400 )); \'
  printf "\t%s\n" '  echo "Query: collection=$$COL tag=$$TAG since=$$SINCE ($$DAYS d)"; \'
  printf "\t%s\n" '  jq -n --arg tag "$$TAG" --argjson since $$SINCE '\''{'
  printf "\t%s\n" '    limit:200, with_payload:true, with_vectors:false,'
  printf "\t%s\n" '    filter:{ must:['
  printf "\t%s\n" '      { key:"tags",           match:{ value:$tag } },'
  printf "\t%s\n" '      { key:"ingested_at_ts", range:{ gte:$since } }'
  printf "\t%s\n" '    ] }'
  printf "\t%s\n" '  }'\'' | \'
  printf "\t%s\n" '  curl -sS -X POST "$$(QDR)/collections/$$COL/points/scroll" \'
  printf "\t%s\n" "    -H 'Content-Type: application/json' -d @- | \\"
  printf "\t%s\n" "  jq -c '{count:((.result.points // [])|length),items:((.result.points // [])|map({id, payload}))}'"
  printf "%s\n" "### <<< HEVA PARAM END <<<"
} >> "${MAKEFILE}.tmp"

mv -f "${MAKEFILE}.tmp" "${MAKEFILE}"
echo "✅ Repaired qdr-since (v2). Backup at ${MAKEFILE}.bak.qdr_since_v2"
echo "Try:"
echo "  make qdr-since                 # defaults: DAYS=7 TAG=THREAT_ACTOR COL=heva_docs"
echo '  make qdr-since DAYS=30'
echo '  make qdr-since TAG="INDICATOR"'
echo '  make qdr-since COL=heva_docs QDR=http://127.0.0.1:6333'
