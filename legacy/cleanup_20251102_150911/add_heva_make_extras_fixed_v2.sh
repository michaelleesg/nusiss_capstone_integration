#!/usr/bin/env bash
# WSL-safe; idempotent. Appends (and dedupes) a clean HEVA EXTRAS block to Makefile.
# - Fixes broken heredocs/quotes in qdr-seed
# - Uses jq -n to build JSON; pipes to curl with -d @-
# - Real tabs in recipes; no set -euo to avoid closing WSL windows on error

MAKEFILE="Makefile"
START="### >>> HEVA EXTRAS >>>"
END="### <<< HEVA EXTRAS <<<"

if [ ! -f "$MAKEFILE" ]; then
  echo "❌ $MAKEFILE not found in $(pwd)"
  exit 1
fi

cp -f "$MAKEFILE" "${MAKEFILE}.bak.heva_extras_v2" 2>/dev/null || true

# Strip ALL existing EXTRAS blocks
awk -v s="$START" -v e="$END" '
  BEGIN{skip=0}
  index($0,s){skip=1; next}
  index($0,e){skip=0; next}
  !skip{print}
' "${MAKEFILE}.bak.heva_extras_v2" > "${MAKEFILE}.tmp"

# Append clean EXTRAS block
cat >> "${MAKEFILE}.tmp" <<'MAKE'
### >>> HEVA EXTRAS >>>
SHELL := /bin/bash
QDR ?= http://127.0.0.1:6333

# Seed one demo THREAT_ACTOR doc into heva_docs with a 384-d zero vector.
# Works whether the collection already exists or not (Qdrant upsert will create it if needed,
# but vector size must match; this uses 384 to match common MiniLM/GTE config).
qdr-seed:
	@NOW=$$(date +%s); \
	echo "Seeding one demo THREAT_ACTOR doc into heva_docs (ingested_at_ts=$$NOW)"; \
	jq -n --argjson now $$NOW '{ \
	  points: [ \
	    { id: 1, \
	      vector: [range(384) | 0], \
	      payload: { \
	        text: "Seed THREAT_ACTOR doc", \
	        source: "seed", \
	        tags: ["THREAT_ACTOR"], \
	        threat_actors: ["TA505"], \
	        ingested_at_ts: $$now \
	      } \
	    } \
	  ] \
	}' | \
	curl -sS -X PUT "$(QDR)/collections/heva_docs/points" \
	  -H 'Content-Type: application/json' -d @- | jq -r '.status // "ok"'

# Danger: delete the heva_docs collection
qdr-wipe-docs:
	@curl -sS -X DELETE "$(QDR)/collections/heva_docs" | jq -r '.status // "ok"' || true

# Danger: delete the heva_v1 collection
qdr-wipe-heva_v1:
	@curl -sS -X DELETE "$(QDR)/collections/heva_v1" | jq -r '.status // "ok"' || true
### <<< HEVA EXTRAS <<<
MAKE

mv "${MAKEFILE}.tmp" "${MAKEFILE}"
echo "OK: Makefile updated (HEVA EXTRAS fixed v2). Backup at Makefile.bak.heva_extras_v2"
echo "Try: make qdr-seed | make qdr-wipe-docs | make qdr-wipe-heva_v1"
