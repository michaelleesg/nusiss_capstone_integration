#!/usr/bin/env bash
# WSL-safe: no set -euo; dedupes any prior HEVA blocks and writes a quote-safe version.

MAKEFILE="Makefile"
START="### >>> HEVA QDRANT TARGETS >>>"
END="### <<< HEVA QDRANT TARGETS <<<"

if [ ! -f "$MAKEFILE" ]; then
  echo "ERROR: $MAKEFILE not found in $(pwd)"
  exit 1
fi

# Heads-up for deps (non-fatal)
for dep in curl jq; do
  command -v "$dep" >/dev/null 2>&1 || echo "WARN: missing dependency: $dep"
done

# Normalize line endings just in case (CRLF can break recipes)
sed -i 's/\r$//' "$MAKEFILE" 2>/dev/null || true

cp -f "$MAKEFILE" "${MAKEFILE}.bak.heva_wsl_v2" 2>/dev/null || true

# Remove any existing HEVA block
awk -v s="$START" -v e="$END" '
  BEGIN{skip=0}
  index($0,s){skip=1; next}
  index($0,e){skip=0; next}
  !skip{print}
' "${MAKEFILE}.bak.heva_wsl_v2" > "${MAKEFILE}.tmp"

# Append a clean, heredoc-based HEVA block (tabs required for recipes)
cat >> "${MAKEFILE}.tmp" <<'MAKE'
### >>> HEVA QDRANT TARGETS >>>
SHELL := /bin/bash
QDR ?= http://127.0.0.1:6333

qdr-ping:
	@echo "Pinging $(QDR)/collections ..."
	@curl -sS "$(QDR)/collections" | jq '.result.collections | length' || true

qdr-count-oct:
	@START=$$(date -d 2025-10-01T00:00:00+08:00 +%s); \
	END=$$(date   -d 2025-11-01T00:00:00+08:00 +%s); \
	echo "Counting heva_v1.ingested_at_ts from $$START to $$END"; \
	curl -sS -X POST "$(QDR)/collections/heva_v1/points/count" \
	  -H "Content-Type: application/json" \
	  -d @- <<JSON | jq '.result // 0'
{ "with_payload": false, "with_vectors": false,
  "filter": { "must": [ { "key": "ingested_at_ts", "range": { "gte": '"$$START"', "lte": '"$$END"' } } ] },
  "limit": 1 }
JSON

qdr-last7:
	@SINCE=$$(( $$(date +%s) - 7*86400 )); \
	echo "Last 7 days (heva_docs.ingested_at_ts >= $$SINCE)"; \
	curl -sS -X POST "$(QDR)/collections/heva_docs/points/scroll" \
	  -H "Content-Type: application/json" \
	  -d @- <<JSON | jq -c '{count: ((.result.points // [])|length), items: ((.result.points // [])|map({id, payload}))}'
{ "limit": 200, "with_payload": true, "with_vectors": false,
  "filter": { "must": [ { "key": "ingested_at_ts", "range": { "gte": '"$$SINCE"' } } ] } }
JSON

qdr-ta-since:
	@SINCE=$$(( $$(date +%s) - 7*86400 )); \
	echo "THREAT_ACTOR since last 7 days (heva_docs)"; \
	curl -sS -X POST "$(QDR)/collections/heva_docs/points/scroll" \
	  -H "Content-Type: application/json" \
	  -d @- <<JSON | jq -c '{count: ((.result.points // [])|length), items: ((.result.points // [])|map({id, payload}))}'
{ "limit": 200, "with_payload": true, "with_vectors": false,
  "filter": { "must": [
    { "key": "tags", "match": { "value": "THREAT_ACTOR" } },
    { "key": "ingested_at_ts", "range": { "gte": '"$$SINCE"' } }
  ] } }
JSON
### <<< HEVA QDRANT TARGETS <<<
MAKE

mv "${MAKEFILE}.tmp" "${MAKEFILE}"
echo "OK: Makefile updated (HEVA WSL-safe v2). Backup at ${MAKEFILE}.bak.heva_wsl_v2"
echo "Try: make qdr-ping | make qdr-count-oct | make qdr-last7 | make qdr-ta-since"
