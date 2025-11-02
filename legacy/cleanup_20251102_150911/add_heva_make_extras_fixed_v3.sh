#!/usr/bin/env bash
# WSL-safe patcher: replaces the HEVA EXTRAS block with a robust, quote-safe version.
# - No `set -euo pipefail` to avoid closing WSL windows on non-zero exits.
# - Idempotent: backs up and dedupes the block each run.

MAKEFILE="Makefile"
START="### >>> HEVA EXTRAS >>>"
END="### <<< HEVA EXTRAS <<<"

if [ ! -f "$MAKEFILE" ]; then
  echo "❌ $MAKEFILE not found in $(pwd)"
  exit 1
fi

cp -f "$MAKEFILE" "${MAKEFILE}.bak.heva_extras_v3" 2>/dev/null || true

# Strip ALL existing HEVA EXTRAS blocks
awk -v s="$START" -v e="$END" '
  BEGIN{skip=0}
  index($0,s){skip=1; next}
  index($0,e){skip=0; next}
  !skip{print}
' "${MAKEFILE}.bak.heva_extras_v3" > "${MAKEFILE}.tmp"

# Append clean EXTRAS block (tabs are required for recipes)
cat >> "${MAKEFILE}.tmp" <<'MAKE'
### >>> HEVA EXTRAS >>>
SHELL := /bin/bash
QDR ?= http://127.0.0.1:6333

# Seed one demo THREAT_ACTOR point into heva_docs with a 384-d zero vector.
qdr-seed:
	@NOW=$$(date +%s); \
	echo "Seeding one demo THREAT_ACTOR doc into heva_docs (ingested_at_ts=$$NOW)"; \
	# Ensure collection exists (384-d Cosine). Ignore if already exists.
	curl -sS -X PUT "$(QDR)/collections/heva_docs" \
	  -H 'Content-Type: application/json' \
	  -d '{ "vectors": { "size": 384, "distance": "Cosine" } }' >/dev/null || true; \
	# Build a correct JSON body entirely in jq, then stream to curl with -d @-
	jq -n --argjson now $$NOW '{
	  points: [
	    {
	      id: 296791,
	      vector: ( [range(384)] | map(0) ),
	      payload: {
	        text: "Recent demo doc (last 7 days)",
	        source: "seed",
	        tags: ["THREAT_ACTOR"],
	        threat_actors: ["TA505"],
	        ingested_at_ts: $now
	      }
	    }
	  ]
	}' | curl -sS -X PUT "$(QDR)/collections/heva_docs/points" \
	      -H 'Content-Type: application/json' -d @- | jq .

# Delete ALL points from heva_docs (safe to run even if empty).
qdr-wipe-docs:
	@echo "Wiping all points from heva_docs …"; \
	jq -n '{filter:{}}' | \
	curl -sS -X POST "$(QDR)/collections/heva_docs/points/delete" \
	  -H 'Content-Type: application/json' -d @- | jq .

# Delete ALL points from heva_v1 (safe to run even if empty).
qdr-wipe-heva_v1:
	@echo "Wiping all points from heva_v1 …"; \
	jq -n '{filter:{}}' | \
	curl -sS -X POST "$(QDR)/collections/heva_v1/points/delete" \
	  -H 'Content-Type: application/json' -d @- | jq .
### <<< HEVA EXTRAS <<<
MAKE

mv "${MAKEFILE}.tmp" "${MAKEFILE}"
echo "OK: Makefile updated (HEVA EXTRAS fixed v3). Backup at ${MAKEFILE}.bak.heva_extras_v3"
echo "Try: make qdr-seed | make qdr-wipe-docs | make qdr-wipe-heva_v1"
