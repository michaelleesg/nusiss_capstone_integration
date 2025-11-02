#!/usr/bin/env bash
set -euo pipefail

MAKEFILE="Makefile"
START_MARK="### >>> HEVA QDRANT TARGETS >>>"
END_MARK="### <<< HEVA QDRANT TARGETS <<<"

[[ -f "$MAKEFILE" ]] || { echo "❌ $MAKEFILE not found in $(pwd)"; exit 1; }

# Ensure bash for recipes
if ! grep -q '^SHELL *:= */bin/bash' "$MAKEFILE"; then
  sed -i '1i SHELL := /bin/bash' "$MAKEFILE"
fi

# Backup
cp -f "$MAKEFILE" "${MAKEFILE}.bak.heva_v2"

# Remove ALL old HEVA blocks
awk -v start="$START_MARK" -v end="$END_MARK" '
  BEGIN{skip=0}
  index($0, start){skip=1; next}
  index($0, end){skip=0; next}
  !skip { print }
' "$MAKEFILE" > "$MAKEFILE.tmp"

# Append fresh single, robust block (no backslashes in jq program /d body)
cat >> "$MAKEFILE.tmp" <<'MAKEBLOCK'

### >>> HEVA QDRANT TARGETS >>>
# Qdrant helpers assume scripts/qdr_helpers.sh exists.
# You can set QDRANT_URL env; default http://127.0.0.1:6333

# Count ingests in Oct 2025 (SGT)
qdr-count-oct:
	@source scripts/qdr_helpers.sh; \
	START=$$(date -d '2025-10-01T00:00:00+08:00' +%s); \
	END=$$(date   -d '2025-11-01T00:00:00+08:00' +%s); \
	echo "Counting heva_v1.ingested_at_ts from $$START to $$END"; \
	qdr_count_window heva_v1 ingested_at_ts "$$START" "$$END"

# Last 7 days from heva_docs by ingested_at_ts
qdr-last7:
	@source scripts/qdr_helpers.sh; \
	SINCE=$$(( $$(date +%s) - 7*86400 )); \
	echo "Last 7 days (heva_docs.ingested_at_ts >= $$SINCE)"; \
	qdr_range heva_docs ingested_at_ts "$$SINCE" "" 50

# THREAT_ACTOR since last 7 days from heva_docs (null-safe)
qdr-ta-since:
	@SINCE=$$(( $$(date +%s) - 7*86400 )); \
	URL="$${QDRANT_URL:-http://127.0.0.1:6333}"; \
	echo "THREAT_ACTOR since last 7 days (heva_docs):"; \
	curl -s -X POST "$$URL/collections/heva_docs/points/scroll" \
	  -H 'Content-Type: application/json' \
	  -d "$$(jq -n --argjson SINCE $$SINCE '{"limit":50,"with_payload":true,"with_vectors":false,"filter":{"must":[{"match":{"key":"tags","value":"THREAT_ACTOR"}},{"key":"ingested_at_ts","range":{"gte":$SINCE}}]}}')" \
	| jq '(.result.points // []) | map({source: .payload.source, tags: .payload.tags, ingested_at_ts: .payload.ingested_at_ts})'

### <<< HEVA QDRANT TARGETS <<<
MAKEBLOCK

mv "$MAKEFILE.tmp" "$MAKEFILE"

# Fix possible clock-skew warnings on some filesystems
touch "$MAKEFILE"

echo "✅ Makefile updated (HEVA v2). Backup at ${MAKEFILE}.bak.heva_v2"
echo "Try: make qdr-count-oct | make qdr-last7 | make qdr-ta-since"
