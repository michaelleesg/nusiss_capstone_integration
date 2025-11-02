#!/usr/bin/env bash
# WSL-safe: no set -euo; idempotent; dedupes previous EXTRAS block.

MAKEFILE="Makefile"
START="### >>> HEVA EXTRAS TARGETS >>>"
END="### <<< HEVA EXTRAS TARGETS <<<"

if [ ! -f "$MAKEFILE" ]; then
  echo "❌ $MAKEFILE not found in $(pwd)"
  exit 1
fi

cp -f "$MAKEFILE" "${MAKEFILE}.bak.heva_extras" 2>/dev/null || true

# Strip any prior EXTRAS block
awk -v s="$START" -v e="$END" '
  BEGIN { skip=0 }
  index($0,s) { skip=1; next }
  index($0,e) { skip=0; next }
  !skip { print }
' "${MAKEFILE}.bak.heva_extras" > "${MAKEFILE}.tmp"

cat >> "${MAKEFILE}.tmp" <<'MAKE'
### >>> HEVA EXTRAS TARGETS >>>
SHELL := /bin/bash
QDR ?= http://127.0.0.1:6333

# Seed one demo doc into heva_docs (tags=["THREAT_ACTOR"], threat_actors=["TA505"])
qdr-seed:
	@NOW=$$(date +%s); \
	jq -n --arg now "$$NOW" '{
	  points:[{
	    id: 296792,
	    vector: [0,0,0,0],
	    payload: {
	      text: "Seeded demo doc",
	      source: "seed",
	      tags: ["THREAT_ACTOR"],
	      threat_actors: ["TA505"],
	      ingested_at_ts: ($now|tonumber)
	    }
	  }]
	}' | curl -sS -X PUT "$(QDR)/collections/heva_docs/points" -H 'Content-Type: application/json' -d @- >/dev/null && \
	echo "Seeded one demo doc into heva_docs."

# Delete the heva_docs collection (DANGER)
qdr-wipe-docs:
	@curl -sS -X DELETE "$(QDR)/collections/heva_docs" >/dev/null || true; \
	echo "Wipe request sent for heva_docs."

# Delete the heva_v1 collection (DANGER)
qdr-wipe-heva_v1:
	@curl -sS -X DELETE "$(QDR)/collections/heva_v1" >/dev/null || true; \
	echo "Wipe request sent for heva_v1."
### <<< HEVA EXTRAS TARGETS <<<
MAKE

mv "${MAKEFILE}.tmp" "${MAKEFILE}"
echo "OK: Makefile updated (HEVA EXTRAS). Backup at ${MAKEFILE}.bak.heva_extras"
echo "Try: make qdr-seed | make qdr-wipe-docs | make qdr-wipe-heva_v1"
