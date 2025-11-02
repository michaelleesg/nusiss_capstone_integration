#!/usr/bin/env bash
set -euo pipefail

MAKEFILE="Makefile"
START_MARK="### >>> HEVA QDRANT TARGETS >>>"
END_MARK="### <<< HEVA QDRANT TARGETS <<<"

[[ -f "$MAKEFILE" ]] || { echo "❌ $MAKEFILE not found in $(pwd)"; exit 1; }

cp -f "$MAKEFILE" "${MAKEFILE}.bak.heva_force_v2"

# Strip any existing injected HEVA blocks
awk -v s="$START_MARK" -v e="$END_MARK" '
  BEGIN{skip=0}
  index($0,s){skip=1; next}
  index($0,e){skip=0; next}
  !skip{print}
' "${MAKEFILE}.bak.heva_force_v2" > "${MAKEFILE}.tmp"

cat >> "${MAKEFILE}.tmp" <<'MAKE'
### >>> HEVA QDRANT TARGETS >>>
SHELL := /bin/bash
QDRANT_URL ?= http://127.0.0.1:6333

# Compact jq programs. IMPORTANT: escape $ as $$ so Make doesn't eat jq variables.
JQ_POINTS = '(.result.points // []) as $$p | {count: ($$p|length), items: ($$p|map({id, payload}))}'
JQ_PAYLOADS = '(.result.points // []) | map(.payload // {})'
JQ_TA = '(.result.points // []) | map(.payload // {}) | map({source, tags, ingested_at_ts})'

qdr-ping:
	@echo "Pinging $(QDRANT_URL)/collections ..."
	@curl -sS "$(QDRANT_URL)/collections" | jq -r '.result.collections[].name' || { echo "⚠️ Qdrant not reachable"; exit 0; }

qdr-count-oct:
	@START=$$(date -d '2025-10-01T00:00:00+08:00' +%s); \
	END=$$(date -d '2025-11-01T00:00:00+08:00' +%s); \
	echo "Counting heva_v1.ingested_at_ts from $$START to $$END"; \
	curl -sS -X POST "$(QDRANT_URL)/collections/heva_v1/points/count" \
		-H 'Content-Type: application/json' \
		-d "$$({ \
			printf '{\"exact\":true,\"filter\":{\"must\":[{\"key\":\"ingested_at_ts\",\"range\":{\"gte\":%s,\"lt\":%s}}]}}' $$START $$END; \
		})" | jq -r '.result.count // 0'

qdr-last7:
	@SINCE=$$(( $$(date +%s) - 7*86400 )); \
	echo "Last 7 days (heva_docs.ingested_at_ts >= $$SINCE)"; \
	curl -sS -X POST "$(QDRANT_URL)/collections/heva_docs/points/scroll" \
		-H 'Content-Type: application/json' \
		-d "$$({ \
			printf '{\"limit\":50,\"with_payload\":true,\"with_vectors\":false,\"filter\":{\"must\":[{\"key\":\"ingested_at_ts\",\"range\":{\"gte\":%s}}]}}' $$SINCE; \
		})" | jq -c $(JQ_POINTS)

qdr-ta-since:
	@SINCE=$$(( $$(date +%s) - 7*86400 )); \
	echo "THREAT_ACTOR since last 7 days (heva_docs)"; \
	curl -sS -X POST "$(QDRANT_URL)/collections/heva_docs/points/scroll" \
		-H 'Content-Type: application/json' \
		-d "$$({ \
			printf '{\"limit\":50,\"with_payload\":true,\"with_vectors\":false,\"filter\":{\"must\":[{\"match\":{\"key\":\"tags\",\"value\":\"THREAT_ACTOR\"}},{\"key\":\"ingested_at_ts\",\"range\":{\"gte\":%s}}]}}' $$SINCE; \
		})" | jq -c $(JQ_TA)

### <<< HEVA QDRANT TARGETS <<<
MAKE

mv "${MAKEFILE}.tmp" "${MAKEFILE}"
echo "✅ Makefile updated (HEVA force v2). Backup at ${MAKEFILE}.bak.heva_force_v2"
echo "Try: make qdr-ping | make qdr-count-oct | make qdr-last7 | make qdr-ta-since"
