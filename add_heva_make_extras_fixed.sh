#!/usr/bin/env bash
# WSL-safe: no set -euo; idempotent; appends/dedupes HEVA EXTRAS targets.

MAKEFILE="Makefile"
START="### >>> HEVA EXTRAS TARGETS >>>"
END="### <<< HEVA EXTRAS TARGETS <<<"

if [ ! -f "$MAKEFILE" ]; then
  echo "❌ $MAKEFILE not found in $(pwd)"
  exit 1
fi

# Heads-up for deps (non-fatal)
for dep in curl jq; do
  command -v "$dep" >/dev/null 2>&1 || echo "⚠️  Missing dependency: $dep"
done

cp -f "$MAKEFILE" "${MAKEFILE}.bak.heva_extras_fix" 2>/dev/null || true

# Strip ALL existing EXTRAS blocks (if any)
awk -v s="$START" -v e="$END" '
  BEGIN { skip=0 }
  index($0,s) { skip=1; next }
  index($0,e) { skip=0; next }
  !skip { print }
' "${MAKEFILE}.bak.heva_extras_fix" > "${MAKEFILE}.tmp"

# Append clean EXTRAS block (ensure real tabs for recipes)
cat >> "${MAKEFILE}.tmp" <<'MAKE'
### >>> HEVA EXTRAS TARGETS >>>
# Extra convenience targets. Requires curl + jq. QDR can be overriden: make qdr-seed QDR=http://localhost:6333
QDR ?= http://127.0.0.1:6333

qdr-seed:
	@NOW=$$(date +%s); \
	echo "Seeding one demo THREAT_ACTOR doc into heva_docs (ingested_at_ts=$$NOW)"; \
	# ensure collection exists (idempotent); vectors size is arbitrary since we only scroll/count here
	curl -sS -X PUT "$(QDR)/collections/heva_docs" \
	  -H 'Content-Type: application/json' \
	  -d '{ "vectors": { "size": 4, "distance": "Cosine" } }' >/dev/null || true; \
	jq -n --argjson now $$NOW '{
	  points: [{
	    id: $now,
	    vector: [0,0,0,0],
	    payload: {
	      text: "Seed THREAT_ACTOR doc",
	      source: "seed",
	      tags: ["THREAT_ACTOR"],
	      threat_actors: ["TA505"],
	      ingested_at_ts: $now
	    }
	  }]
	}' | curl -sS -X PUT "$(QDR)/collections/heva_docs/points" \
	  -H 'Content-Type: application/json' -d @- | jq -r '.status' || true

qdr-wipe-docs:
	@echo "Deleting collection heva_docs (DANGER)"; \
	curl -sS -X DELETE "$(QDR)/collections/heva_docs" | jq -r '.status' || true

qdr-wipe-heva_v1:
	@echo "Deleting collection heva_v1 (DANGER)"; \
	curl -sS -X DELETE "$(QDR)/collections/heva_v1" | jq -r '.status' || true
### <<< HEVA EXTRAS TARGETS <<<
MAKE

mv "${MAKEFILE}.tmp" "${MAKEFILE}"
echo "OK: Makefile updated (HEVA EXTRAS fixed). Backup at ${MAKEFILE}.bak.heva_extras_fix"
echo "Try: make qdr-seed | make qdr-wipe-docs | make qdr-wipe-heva_v1"
