#!/usr/bin/env bash
# WSL-safe Makefile patcher (no set -euo). Cleans bad lines and injects a fresh HEVA block.
# Usage (from repo root):
#   chmod +x patch_heva_wsl_safe_clean.sh
#   ./patch_heva_wsl_safe_clean.sh
# Then run:
#   make qdr-ping && make qdr-count-oct && make qdr-last7 && make qdr-ta-since

MAKEFILE="Makefile"
START_MARK="### >>> HEVA QDRANT TARGETS >>>"
END_MARK="### <<< HEVA QDRANT TARGETS <<<"

if [ ! -f "$MAKEFILE" ]; then
  echo "❌ $MAKEFILE not found in $(pwd)"
  exit 1
fi

# 1) Backup
cp -f "$MAKEFILE" "${MAKEFILE}.bak.heva_clean" 2>/dev/null || true

# 2) Global clean-up of known garbage that may have been inserted earlier
#    (safe: deletes lines starting with old prompts or stray 'Try:' banners)
#    We do this on a temp copy to avoid in-place sed issues across platforms.
tmp="${MAKEFILE}.tmp.heva_clean"
cp -f "$MAKEFILE" "$tmp"
# Remove common prompt artifacts and banners anywhere in the file
sed -i -E '/^\(aider-latest\)/d' "$tmp"
sed -i -E '/^OK: Makefile updated/d' "$tmp"
sed -i -E '/^Try: make qdr-ping/d' "$tmp"
sed -i -E '/^curl: \(1\) Protocol/d' "$tmp"
sed -i -E '/^[[:space:]]*# >>> BROKEN HEVA BLOCK START <<</,/^[[:space:]]*# >>> BROKEN HEVA BLOCK END <<</d' "$tmp"

# 3) Strip ALL existing HEVA blocks (between our canonical markers)
awk -v s="$START_MARK" -v e="$END_MARK" '
  BEGIN{skip=0}
  index($0,s){skip=1; next}
  index($0,e){skip=0; next}
  !skip{print}
' "$tmp" > "${MAKEFILE}.tmp"

# 4) Append a fresh, correct HEVA block (tabs required in recipes)
cat >> "${MAKEFILE}.tmp" <<'MAKE'
### >>> HEVA QDRANT TARGETS >>>
SHELL := /bin/bash
QDR ?= http://127.0.0.1:6333

qdr-ping:
	@echo "Pinging $(QDR)/collections ..."
	@curl -sS "$(QDR)/collections" | jq '.result.collections | length' || true

qdr-count-oct:
	@START=$$(date -d '2025-10-01T00:00:00+08:00' +%s); \
	END=$$(date   -d '2025-11-01T00:00:00+08:00' +%s); \
	echo "Counting heva_v1.ingested_at_ts from $$START to $$END"; \
	jq -n --argjson start $$START --argjson end $$END '{ filter: { must: [ { key:"ingested_at_ts", range:{ gte:$start, lte:$end } } ] } }' | \
	curl -sS -X POST "$(QDR)/collections/heva_v1/points/count" \
	  -H 'Content-Type: application/json' -d @- | \
	jq '.result'

qdr-last7:
	@SINCE=$$(( $$(date +%s) - 7*86400 )); \
	echo "Last 7 days (heva_docs.ingested_at_ts >= $$SINCE)"; \
	jq -n --argjson since $$SINCE '{ limit: 200, with_payload:true, with_vectors:false, filter: { must: [ { key:"ingested_at_ts", range:{ gte:$since } } ] } }' | \
	curl -sS -X POST "$(QDR)/collections/heva_docs/points/scroll" \
	  -H 'Content-Type: application/json' -d @- | \
	jq -c '{count: ((.result.points // [])|length), items: ((.result.points // [])|map({id, payload}))}'

qdr-ta-since:
	@SINCE=$$(( $$(date +%s) - 7*86400 )); \
	echo "THREAT_ACTOR since last 7 days (heva_docs)"; \
	jq -n --argjson since $$SINCE '{ limit: 200, with_payload:true, with_vectors:false, filter: { must: [ { key:"tags", match:{ value:"THREAT_ACTOR" } }, { key:"ingested_at_ts", range:{ gte:$since } } ] } }' | \
	curl -sS -X POST "$(QDR)/collections/heva_docs/points/scroll" \
	  -H 'Content-Type: application/json' -d @- | \
	jq -c '{count: ((.result.points // [])|length), items: ((.result.points // [])|map({id, payload}))}'
### <<< HEVA QDRANT TARGETS <<<
MAKE

# 5) Replace Makefile
mv "${MAKEFILE}.tmp" "$MAKEFILE"

# 6) Quick syntax sanity: ensure no recipe lines lost their TAB
#    (Search for lines starting with 4 spaces before a command — common copy/paste issue)
if grep -nE '^[ ]{4}[@a-zA-Z0-9\$\(\)]' "$MAKEFILE" >/dev/null; then
  echo "⚠️  Warning: Found lines that look like recipe commands indented with spaces instead of tabs."
  echo "   Run: awk '/^### >>> HEVA QDRANT TARGETS >>>/,/^### <<< HEVA QDRANT TARGETS <<</' Makefile | cat -n"
fi

echo "OK: Makefile cleaned and updated (HEVA WSL-safe clean). Backup at ${MAKEFILE}.bak.heva_clean"
echo "Try: make qdr-ping | make qdr-count-oct | make qdr-last7 | make qdr-ta-since"
