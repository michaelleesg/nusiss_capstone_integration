#!/usr/bin/env bash
# WSL-safe patcher: dedupe & append HEVA EXTRAS block. No `set -euo` to avoid closing WSL windows.

MAKEFILE="Makefile"
START="### >>> HEVA EXTRAS >>>"
END="### <<< HEVA EXTRAS <<<"

if [ ! -f "$MAKEFILE" ]; then
  echo "❌ $MAKEFILE not found in $(pwd)"
  exit 1
fi

cp -f "$MAKEFILE" "${MAKEFILE}.bak.heva_extras_v4" 2>/dev/null || true

# Strip ALL existing EXTRAS blocks
awk -v s="$START" -v e="$END" '
  BEGIN { skip=0 }
  index($0,s) { skip=1; next }
  index($0,e) { skip=0; next }
  !skip { print }
' "${MAKEFILE}.bak.heva_extras_v4" > "${MAKEFILE}.tmp"

# Append clean EXTRAS block
cat >> "${MAKEFILE}.tmp" <<'MAKE'
### >>> HEVA EXTRAS >>>
SHELL := /bin/bash
QDR ?= http://127.0.0.1:6333

# Seed a demo THREAT_ACTOR point into heva_docs (id=1, 384-d zero vector)
qdr-seed:
	@NOW=$$(date +%s); \
	echo "Seeding one demo THREAT_ACTOR doc into heva_docs (ingested_at_ts=$$NOW)"; \
	curl -sS -X PUT "$(QDR)/collections/heva_docs" \
	  -H "Content-Type: application/json" \
	  -d '{ "vectors": { "size": 384, "distance": "Cosine" } }' >/dev/null || true; \
	BODY=$$(jq -n --argjson now $$NOW '{ \
	  points: [ { \
	    id: 1, \
	    vector: ([range(384)] | map(0)), \
	    payload: { \
	      text: "Seed THREAT_ACTOR doc", \
	      source: "seed", \
	      tags: ["THREAT_ACTOR"], \
	      threat_actors: ["TA505"], \
	      ingested_at_ts: $$now \
	    } \
	  } ] \
	}'); \
	printf "%s" "$$BODY" | curl -sS -X PUT "$(QDR)/collections/heva_docs/points" \
	  -H "Content-Type: application/json" -d @- | jq -c .

# Delete ALL points in heva_docs
qdr-wipe-docs:
	@echo "Deleting ALL points in heva_docs..."; \
	jq -n '{ filter: { must: [] } }' | \
	curl -sS -X POST "$(QDR)/collections/heva_docs/points/delete" \
	  -H "Content-Type: application/json" -d @- | jq -c .

# Delete ALL points in heva_v1
qdr-wipe-heva_v1:
	@echo "Deleting ALL points in heva_v1..."; \
	jq -n '{ filter: { must: [] } }' | \
	curl -sS -X POST "$(QDR)/collections/heva_v1/points/delete" \
	  -H "Content-Type: application/json" -d @- | jq -c .
### <<< HEVA EXTRAS <<<
MAKE

mv "${MAKEFILE}.tmp" "${MAKEFILE}"
echo "OK: Makefile updated (HEVA EXTRAS fixed v4). Backup at ${MAKEFILE}.bak.heva_extras_v4"
echo "Try: make qdr-seed | make qdr-wipe-docs | make qdr-wipe-heva_v1"
