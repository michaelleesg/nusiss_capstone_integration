#!/usr/bin/env bash
# repair_qdr_since.sh
# WSL-safe (no set -euo). Rewrites the qdr-since target with correct quoting & tabs.

MAKEFILE="Makefile"
START_MARK="### >>> HEVA PARAM START >>>"
END_MARK="### <<< HEVA PARAM END <<<"

if [ ! -f "$MAKEFILE" ]; then
  echo "❌ $MAKEFILE not found in $(pwd)"
  exit 1
fi

cp -f "$MAKEFILE" "${MAKEFILE}.bak.qdr_since_repair" 2>/dev/null || true

# Remove any prior PARAM block
awk -v s="$START_MARK" -v e="$END_MARK" '
  BEGIN{skip=0}
  index($0,s){skip=1; next}
  index($0,e){skip=0; next}
  !skip{print}
' "${MAKEFILE}.bak.qdr_since_repair" > "${MAKEFILE}.tmp"

# Append a clean block. We prefix recipe lines with @TAB@, and convert to real TABs after.
cat >> "${MAKEFILE}.tmp" <<'MAKE'
### >>> HEVA PARAM START >>>
.PHONY: qdr-since
qdr-since:
@TAB@@DAYS=$${DAYS:-7}; TAG=$${TAG:-THREAT_ACTOR}; COL=$${COL:-heva_docs}; \
@TAB@  SINCE=$$(( $$(date +%s) - $$DAYS*86400 )); \
@TAB@  echo "Query: collection=$$COL tag=$$TAG since=$$SINCE ($$DAYS d)"; \
@TAB@  jq -n --arg tag "$$TAG" --argjson since $$SINCE '{
@TAB@    limit: 200, with_payload: true, with_vectors: false,
@TAB@    filter: { must: [
@TAB@      { key: "tags",           match: { value: $tag } },
@TAB@      { key: "ingested_at_ts", range: { gte: $since } }
@TAB@    ] }
@TAB@  }' | \
@TAB@  curl -sS -X POST "$$(QDR)/collections/$$COL/points/scroll" \
@TAB@    -H 'Content-Type: application/json' -d @- | \
@TAB@    jq -c '{count: ((.result.points // [])|length), items: ((.result.points // [])|map({id, payload}))}'
### <<< HEVA PARAM END <<<
MAKE

# Convert @TAB@ markers to real tabs at the start of lines
# Use perl for portability with in-place editing on WSL
perl -0777 -pe 's/^@TAB@/\t/mg' "${MAKEFILE}.tmp" > "${MAKEFILE}.new" && mv "${MAKEFILE}.new" "${MAKEFILE}"

echo "✅ Repaired qdr-since. Backup at ${MAKEFILE}.bak.qdr_since_repair"
echo "Try examples:"
echo "  make qdr-since                 # defaults: DAYS=7 TAG=THREAT_ACTOR COL=heva_docs"
echo "  make qdr-since DAYS=30"
echo '  make qdr-since TAG="INDICATOR"'
echo "  make qdr-since COL=heva_docs QDR=http://127.0.0.1:6333"
