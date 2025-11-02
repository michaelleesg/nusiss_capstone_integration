#!/usr/bin/env bash
# WSL-safe Makefile patcher (no set -euo). It:
# 1) Removes any existing HEVA QDRANT TARGETS blocks
# 2) Appends a clean, valid block (with proper tabs)
# 3) Backs up your Makefile as Makefile.bak.heva_wsl_v3

MAKEFILE="Makefile"
START="### >>> HEVA QDRANT TARGETS >>>"
END="### <<< HEVA QDRANT TARGETS <<<"

if [ ! -f "$MAKEFILE" ]; then
  echo "❌ $MAKEFILE not found in $(pwd)"
  exit 1
fi

# Normalize line endings to LF to avoid 'multiple target patterns' from stray CRLF
# If dos2unix exists, use it; else fall back to sed.
if command -v dos2unix >/dev/null 2>&1; then
  dos2unix -q "$MAKEFILE" 2>/dev/null || true
else
  # sed fallback: remove \r
  sed -i 's/\r$//' "$MAKEFILE" 2>/dev/null || true
fi

cp -f "$MAKEFILE" "${MAKEFILE}.bak.heva_wsl_v3" 2>/dev/null || true

# Strip ALL existing HEVA blocks
awk -v s="$START" -v e="$END" '
  BEGIN{skip=0}
  index($0,s){skip=1; next}
  index($0,e){skip=0; next}
  !skip{print}
' "${MAKEFILE}.bak.heva_wsl_v3" > "${MAKEFILE}.tmp"

# Append clean block with proper tabs in recipes
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
	jq -n --argjson start $$START --argjson end $$END '{
	  with_payload:false, with_vectors:false,
	  filter:{ must:[ { key:"ingested_at_ts", range:{ gte:$start, lte:$end } } ] }
	}' | \
	curl -sS -X POST "$(QDR)/collections/heva_v1/points/count" \
	  -H 'Content-Type: application/json' -d @- | \
	jq '.result'

qdr-last7:
	@SINCE=$$(( $$(date +%s) - 7*86400 )); \
	echo "Last 7 days (heva_docs.ingested_at_ts >= $$SINCE)"; \
	jq -n --argjson since $$SINCE '{
	  limit:200, with_payload:true, with_vectors:false,
	  filter:{ must:[ { key:"ingested_at_ts", range:{ gte:$since } } ] }
	}' | \
	curl -sS -X POST "$(QDR)/collections/heva_docs/points/scroll" \
	  -H 'Content-Type: application/json' -d @- | \
	jq -c '{count: ((.result.points // [])|length), items: ((.result.points // [])|map({id, payload}))}'

qdr-ta-since:
	@SINCE=$$(( $$(date +%s) - 7*86400 )); \
	echo "THREAT_ACTOR since last 7 days (heva_docs)"; \
	jq -n --argjson since $$SINCE '{
	  limit:200, with_payload:true, with_vectors:false,
	  filter:{ must:[
	    { key:"tags", match:{ value:"THREAT_ACTOR" } },
	    { key:"ingested_at_ts", range:{ gte:$since } }
	  ] }
	}' | \
	curl -sS -X POST "$(QDR)/collections/heva_docs/points/scroll" \
	  -H 'Content-Type: application/json' -d @- | \
	jq -c '{count: ((.result.points // [])|length), items: ((.result.points // [])|map({id, payload}))}'
### <<< HEVA QDRANT TARGETS <<<
MAKE

mv "${MAKEFILE}.tmp" "${MAKEFILE}"

echo "OK: Makefile updated (HEVA WSL-safe v3). Backup at ${MAKEFILE}.bak.heva_wsl_v3"
echo "Try: make qdr-ping | make qdr-count-oct | make qdr-last7 | make qdr-ta-since"
