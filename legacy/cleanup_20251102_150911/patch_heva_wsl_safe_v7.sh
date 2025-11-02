#!/usr/bin/env bash
# WSL-safe Makefile patcher (no set -euo). Dedupes old HEVA blocks and appends a compact, jq-based block.
# Usage: bash patch_heva_wsl_safe_v7.sh

MAKEFILE="Makefile"
START_MARK="### >>> HEVA QDRANT TARGETS >>>"
END_MARK="### <<< HEVA QDRANT TARGETS <<<"

if [ ! -f "$MAKEFILE" ]; then
  echo "❌ $MAKEFILE not found in $(pwd)"
  exit 1
fi

cp -f "$MAKEFILE" "${MAKEFILE}.bak.heva_v7" 2>/dev/null || true

# Strip ALL existing HEVA blocks
awk -v s="$START_MARK" -v e="$END_MARK" '
  BEGIN{skip=0}
  index($0,s){skip=1; next}
  index($0,e){skip=0; next}
  !skip{print}
' "${MAKEFILE}.bak.heva_v7" > "${MAKEFILE}.tmp"

# Append clean block — note: use *compact one-line jq* programs to avoid stray backslashes
cat >> "${MAKEFILE}.tmp" <<'MAKE'
### >>> HEVA QDRANT TARGETS >>>
SHELL := /bin/bash
QDR ?= http://127.0.0.1:6333

qdr-ping:
	@echo "Pinging $(QDR)/collections ..."
	@curl -sS "$(QDR)/collections" | jq '.result.collections | length' || true

qdr-count-oct:
	@START=$$(date -d '2025-10-01T00:00:00+08:00' +%s); END=$$(date -d '2025-11-01T00:00:00+08:00' +%s); \
	echo "Counting heva_v1.ingested_at_ts from $$START to $$END"; \
	jq -n --argjson s $$START --argjson e $$END '{"with_payload":false,"with_vectors":false,"filter":{"must":[{"key":"ingested_at_ts","range":{"gte":$$s,"lte":$$e}}]},"limit":1}' | \
	curl -sS -X POST "$(QDR)/collections/heva_v1/points/count" -H 'Content-Type: application/json' -d @- | jq '.result'

qdr-last7:
	@SINCE=$$(( $$(date +%s) - 7*86400 )); \
	echo "Last 7 days (heva_docs.ingested_at_ts >= $$SINCE)"; \
	jq -n --argjson s $$SINCE '{"limit":200,"with_payload":true,"with_vectors":false,"filter":{"must":[{"key":"ingested_at_ts","range":{"gte":$$s}}]}}' | \
	curl -sS -X POST "$(QDR)/collections/heva_docs/points/scroll" -H 'Content-Type: application/json' -d @- | \
	jq -c '{count: ((.result.points // [])|length), items: ((.result.points // [])|map({id, payload}))}'

qdr-ta-since:
	@SINCE=$$(( $$(date +%s) - 7*86400 )); \
	echo "THREAT_ACTOR since last 7 days (heva_docs)"; \
	jq -n --argjson s $$SINCE '{"limit":200,"with_payload":true,"with_vectors":false,"filter":{"must":[{"key":"tags","match":{"value":"THREAT_ACTOR"}},{"key":"ingested_at_ts","range":{"gte":$$s}}]}}' | \
	curl -sS -X POST "$(QDR)/collections/heva_docs/points/scroll" -H 'Content-Type: application/json' -d @- | \
	jq -c '{count: ((.result.points // [])|length), items: ((.result.points // [])|map({id, payload}))}'
### <<< HEVA QDRANT TARGETS <<<
MAKE

mv -f "${MAKEFILE}.tmp" "${MAKEFILE}"
echo "OK: Makefile updated (HEVA WSL-safe v7). Backup at ${MAKEFILE}.bak.heva_v7"
echo "Try: make qdr-ping | make qdr-count-oct | make qdr-last7 | make qdr-ta-since"
