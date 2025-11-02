\
#!/usr/bin/env bash
# WSL-safe HEVA Makefile patcher (v4)
# - Normalizes Makefile line endings to LF
# - Dedupes any prior HEVA blocks
# - Appends clean targets using here-doc JSON (no single quotes in recipes)
# - Uses /bin/bash and avoids strict -euo to prevent terminal auto-close on error

MAKEFILE="Makefile"
START_MARK="### >>> HEVA QDRANT TARGETS >>>"
END_MARK="### <<< HEVA QDRANT TARGETS <<<"

# 0) Basic checks
if [ ! -f "$MAKEFILE" ]; then
  echo "❌ $MAKEFILE not found in $(pwd)"
  exit 1
fi

cp -f "$MAKEFILE" "${MAKEFILE}.bak.heva_wsl_v4" 2>/dev/null || true

# 1) Normalize CRLF -> LF (use dos2unix if present; else sed)
if command -v dos2unix >/dev/null 2>&1; then
  dos2unix -q "$MAKEFILE" 2>/dev/null || true
else
  # sed fallback (in-place edit)
  sed -i 's/\r$//' "$MAKEFILE" 2>/dev/null || true
fi

# 2) Strip any existing HEVA blocks
awk -v s="$START_MARK" -v e="$END_MARK" '
  BEGIN { skip=0 }
  index($0,s) { skip=1; next }
  index($0,e) { skip=0; next }
  !skip { print }
' "$MAKEFILE" > "${MAKEFILE}.tmp"

# 3) Append fresh, tab-correct block
cat >> "${MAKEFILE}.tmp" <<'MAKE'
### >>> HEVA QDRANT TARGETS >>>
SHELL := /bin/bash
QDR ?= http://127.0.0.1:6333

qdr-ping:
	@echo "Pinging $(QDR)/collections ..."
	@curl -sS "$(QDR)/collections" | jq '.result.collections | length' || true

qdr-count-oct:
	@START=$$(date -d "2025-10-01T00:00:00+08:00" +%s); \
	END=$$(date   -d "2025-11-01T00:00:00+08:00" +%s); \
	echo "Counting heva_v1.ingested_at_ts from $$START to $$END"; \
	cat > /tmp/qdr_count.json <<EOF; \
	{ \
	  "with_payload": false, "with_vectors": false, \
	  "filter": { "must": [ { "key": "ingested_at_ts", "range": { "gte": $$START, "lte": $$END } } ] }, \
	  "limit": 1 \
	} \
EOF \
	; curl -sS -X POST "$(QDR)/collections/heva_v1/points/count" \
	  -H "Content-Type: application/json" --data-binary @/tmp/qdr_count.json | \
	  jq ".result"

qdr-last7:
	@SINCE=$$(( $$(date +%s) - 7*86400 )); \
	echo "Last 7 days (heva_docs.ingested_at_ts >= $$SINCE)"; \
	cat > /tmp/qdr_last7.json <<EOF; \
	{ \
	  "limit": 200, "with_payload": true, "with_vectors": false, \
	  "filter": { "must": [ { "key": "ingested_at_ts", "range": { "gte": $$SINCE } } ] } \
	} \
EOF \
	; curl -sS -X POST "$(QDR)/collections/heva_docs/points/scroll" \
	  -H "Content-Type: application/json" --data-binary @/tmp/qdr_last7.json | \
	  jq -c '{count: ((.result.points // [])|length), items: ((.result.points // [])|map({id, payload}))}'

qdr-ta-since:
	@SINCE=$$(( $$(date +%s) - 7*86400 )); \
	echo "THREAT_ACTOR since last 7 days (heva_docs)"; \
	cat > /tmp/qdr_ta_since.json <<EOF; \
	{ \
	  "limit": 200, "with_payload": true, "with_vectors": false, \
	  "filter": { "must": [ \
	    { "key": "tags", "match": { "value": "THREAT_ACTOR" } }, \
	    { "key": "ingested_at_ts", "range": { "gte": $$SINCE } } \
	  ] } \
	} \
EOF \
	; curl -sS -X POST "$(QDR)/collections/heva_docs/points/scroll" \
	  -H "Content-Type: application/json" --data-binary @/tmp/qdr_ta_since.json | \
	  jq -c '{count: ((.result.points // [])|length), items: ((.result.points // [])|map({id, payload}))}'
### <<< HEVA QDRANT TARGETS <<<
MAKE

# 4) Move into place
mv "${MAKEFILE}.tmp" "$MAKEFILE"

echo "OK: Makefile updated (HEVA WSL-safe v4). Backup at ${MAKEFILE}.bak.heva_wsl_v4"
echo "Try: make qdr-ping | make qdr-count-oct | make qdr-last7 | make qdr-ta-since"
