#!/usr/bin/env bash
# WSL-safe: no subshell temp hacks; exit on errors but avoid abrupt window closes.
set -euo pipefail

MAKEFILE="Makefile"
START_MARK="### >>> HEVA QDRANT TARGETS >>>"
END_MARK="### <<< HEVA QDRANT TARGETS <<<"

if [[ ! -f "$MAKEFILE" ]]; then
  echo "❌ $MAKEFILE not found in $(pwd)"
  exit 1
fi

cp -f "$MAKEFILE" "${MAKEFILE}.bak.heva_clean"

# 1) Strip ALL existing HEVA blocks
awk -v s="$START_MARK" -v e="$END_MARK" '
  BEGIN{skip=0}
  index($0,s){skip=1; next}
  index($0,e){skip=0; next}
  !skip{print}
' "${MAKEFILE}.bak.heva_clean" > "${MAKEFILE}.tmp"

# 2) Append a clean HEVA block. jq programs are one-line (no backslashes).
#    Recipes use /bin/bash explicitly.
cat >> "${MAKEFILE}.tmp" <<'MAKE'
### >>> HEVA QDRANT TARGETS >>>
SHELL := /bin/bash
QDR ?= http://127.0.0.1:6333

qdr-count-oct:
	@START=$$(date -d '2025-10-01T00:00:00+08:00' +%s); \
	END=$$(date   -d '2025-11-01T00:00:00+08:00' +%s); \
	echo "Counting heva_v1.ingested_at_ts from $$START to $$END"; \
	curl -s -X POST "$${QDR}/collections/heva_v1/points/count" \
	  -H 'Content-Type: application/json' \
	  -d "{\"exact\": true, \"filter\": {\"must\": [ {\"key\": \"ingested_at_ts\", \"range\": {\"gte\": $$START, \"lt\": $$END}} ]}}" \
	| jq -r '.result.count // 0'

qdr-last7:
	@SINCE=$$(( $$(date +%s) - 7*86400 )); \
	echo "Last 7 days (heva_docs.ingested_at_ts >= $$SINCE)"; \
	curl -s -X POST "$${QDR}/collections/heva_docs/points/scroll" \
	  -H 'Content-Type: application/json' \
	  -d "{\"limit\":50,\"with_payload\":true,\"with_vectors\":false,\"filter\":{\"must\":[{\"key\":\"ingested_at_ts\",\"range\":{\"gte\":$$SINCE}}]}}" \
	| jq -c 'def brief:{id,payload}; (.result.points // []) as $$p | {count: ($$p|length), items: ($$p|map(brief))}'

qdr-ta-since:
	@SINCE=$$(( $$(date +%s) - 7*86400 )); \
	echo "THREAT_ACTOR since last 7 days (heva_docs):"; \
	curl -s -X POST "$${QDR}/collections/heva_docs/points/scroll" \
	  -H 'Content-Type: application/json' \
	  -d "{\"limit\":50,\"with_payload\":true,\"with_vectors\":false,\"filter\":{\"must\":[{\"match\":{\"key\":\"tags\",\"value\":\"THREAT_ACTOR\"}},{\"key\":\"ingested_at_ts\",\"range\":{\"gte\":$$SINCE}}]}}" \
	| jq -c '(.result.points // []) | map(.payload) | map({source, tags, ingested_at_ts})'
### <<< HEVA QDRANT TARGETS <<<
MAKE

# 3) Move into place
mv "${MAKEFILE}.tmp" "${MAKEFILE}"

echo "✅ Makefile updated (HEVA clean). Backup at ${MAKEFILE}.bak.heva_clean"
echo "Try: make qdr-count-oct | make qdr-last7 | make qdr-ta-since"
