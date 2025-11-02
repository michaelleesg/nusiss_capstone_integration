#!/usr/bin/env bash
# fix_heva_targets_force.sh
# Purpose: Cleanly (re)install HEVA/Qdrant Make targets without duplicate recipes
# Safe for WSL: single shot, no temp subshell hacks. Exits on error.
set -euo pipefail

MAKEFILE="Makefile"
START_MARK="### >>> HEVA QDRANT TARGETS >>>"
END_MARK="### <<< HEVA QDRANT TARGETS <<<"

if [[ ! -f "$MAKEFILE" ]]; then
  echo "❌ $MAKEFILE not found in $(pwd)"
  exit 1
fi

cp -f "$MAKEFILE" "${MAKEFILE}.bak.heva_force"

# 1) Drop any prior HEVA marker blocks
awk -v s="$START_MARK" -v e="$END_MARK" '
  BEGIN{skip=0}
  index($0,s){skip=1; next}
  index($0,e){skip=0; next}
  !skip{print}
' "${MAKEFILE}.bak.heva_force" > "${MAKEFILE}.tmp1"

# 2) Drop any stray duplicate target definitions (qdr-*), even if outside markers
awk '
  # start of a target we manage (column 0, ends with ":" exactly these names)
  /^[[:alnum:]_-]+:[[:space:]]*$/ {
    tgt=$0
    name=$0
    sub(/[[:space:]]*:.*/,"",name)
    if (name=="qdr-count-oct" || name=="qdr-last7" || name=="qdr-ta-since" || name=="qdr-ping") {
      in_skip=1
      next
    }
  }
  # next top-level target line ends a skipped block
  in_skip && /^[[:alnum:]_-]+:[[:space:]]*$/ { in_skip=0 }
  !in_skip { print }
' "${MAKEFILE}.tmp1" > "${MAKEFILE}.tmp2"

# 3) Append a single clean HEVA block
{
  printf "%s\n" ""
  printf "%s\n" "$START_MARK"
  cat <<'MAKE'
SHELL := /bin/bash
# If you export QDRANT_URL, we will use it; otherwise default to local.
QDRANT_URL ?= http://127.0.0.1:6333

# Sanity check: list collection names if Qdrant is reachable
qdr-ping:
	@echo "Pinging $(QDRANT_URL)/collections ..."
	@curl -sfSL "$(QDRANT_URL)/collections" \
	  | jq -r '.result | keys[]?' || { echo "Ping failed"; exit 1; }

# Count heva_v1.ingested_at_ts in October 2025 (Singapore time window)
qdr-count-oct:
	@START=$$(date -d '2025-10-01T00:00:00+08:00' +%s); \
	END=$$(date   -d '2025-11-01T00:00:00+08:00' +%s); \
	echo "Counting heva_v1.ingested_at_ts from $$START to $$END"; \
	curl -s -X POST "$(QDRANT_URL)/collections/heva_v1/points/count" \
	  -H 'Content-Type: application/json' \
	  -d "{\"exact\":true,\"filter\":{\"must\":[{\"key\":\"ingested_at_ts\",\"range\":{\"gte\":$$START,\"lt\":$$END}}]}}" \
	  | jq -r '.result.count // 0'

# Last 7 days from heva_docs by ingested_at_ts
qdr-last7:
	@SINCE=$$(( $$(date +%s) - 7*86400 )); \
	echo "Last 7 days (heva_docs.ingested_at_ts >= $$SINCE)"; \
	curl -s -X POST "$(QDRANT_URL)/collections/heva_docs/points/scroll" \
	  -H 'Content-Type: application/json' \
	  -d "{\"limit\":50,\"with_payload\":true,\"with_vectors\":false, \
	       \"filter\":{\"must\":[{\"key\":\"ingested_at_ts\",\"range\":{\"gte\":$$SINCE}}]}}" \
	  | jq 'def brief: {id, payload}; (.result.points // []) as $p | {count: ($p|length), items: ($p|map(brief))}'

# THREAT_ACTOR since last 7 days (null-safe)
qdr-ta-since:
	@SINCE=$$(( $$(date +%s) - 7*86400 )); \
	echo "THREAT_ACTOR since last 7 days (heva_docs)"; \
	curl -s -X POST "$(QDRANT_URL)/collections/heva_docs/points/scroll" \
	  -H 'Content-Type: application/json' \
	  -d "{\"limit\":50,\"with_payload\":true,\"with_vectors\":false, \
	       \"filter\":{\"must\":[ \
	         {\"match\":{\"key\":\"tags\",\"value\":\"THREAT_ACTOR\"}}, \
	         {\"key\":\"ingested_at_ts\",\"range\":{\"gte\":$$SINCE}} \
	       ]}}" \
	  | jq -r '(.result.points // []) \
	           | map({source: (.payload.source // null), \
	                  tags:   (.payload.tags   // []),   \
	                  ingested_at_ts: (.payload.ingested_at_ts // null)}) \
	           | (if length==0 then "[]" else . end)'
MAKE
  printf "%s\n" "$END_MARK"
} >> "${MAKEFILE}.tmp2"

mv "${MAKEFILE}.tmp2" "$MAKEFILE"
rm -f "${MAKEFILE}.tmp1"

echo "✅ Makefile updated (HEVA force). Backup at ${MAKEFILE}.bak.heva_force"
echo "Try: make qdr-ping | make qdr-count-oct | make qdr-last7 | make qdr-ta-since"
