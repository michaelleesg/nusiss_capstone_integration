#!/usr/bin/env bash
set -euo pipefail

# patch_make_qdrant_targets.sh
# - Ensures scripts/qdr_helpers.sh exists (creates minimal helpers if missing)
# - Appends Qdrant Makefile targets (idempotent)
# - Forces Make to use bash so [[ .. ]] etc. won't break
# - Prints quick usage

require_repo() {
  if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "❌ Run this from your repo root."; exit 1
  fi
}

ensure_helpers() {
  mkdir -p scripts
  if [ ! -f scripts/qdr_helpers.sh ]; then
    cat > scripts/qdr_helpers.sh <<'SH'
# POSIX-safe Qdrant helpers (bash recommended)
qdr_scroll() {
  COL="$1"; JSON="$2"
  curl -s -X POST "${QDRANT_URL:-http://127.0.0.1:6333}/collections/$COL/points/scroll" \
    -H 'Content-Type: application/json' -d "$JSON" \
  | jq 'def brief: {id, payload}; .result.points as $p | {count: ($p|length), items: ($p|map(brief))}'
}

qdr_range() {
  COL="$1"; FIELD="$2"; SINCE="$3"; UNTIL="${4:-}"; LIMIT="${5:-5}"
  RANGE="\"gte\":$SINCE"; [ -n "$UNTIL" ] && RANGE="$RANGE, \"lt\": $UNTIL"
  qdr_scroll "$COL" '{
    "limit": '"$LIMIT"', "with_payload": true, "with_vectors": false,
    "filter": { "must": [ { "key": "'"$FIELD"'", "range": { '"$RANGE"' } } ] }
  }'
}

qdr_count_window() {
  COL="$1"; FIELD="$2"; START="$3"; END="$4"
  curl -s -X POST "${QDRANT_URL:-http://127.0.0.1:6333}/collections/$COL/points/count" \
    -H 'Content-Type: application/json' \
    -d '{ "exact": true, "filter": { "must": [ { "key": "'"$FIELD"'", "range": { "gte": '"$START"', "lt": '"$END"' } } ] } }' \
  | jq -r '.result.count // 0'
}

qdr_tag_since() {
  COL="$1"; TAG="$2"; SINCE="$3"; FIELD="${4:-ingested_at_ts}"; LIMIT="${5:-5}"
  qdr_scroll "$COL" '{
    "limit": '"$LIMIT"', "with_payload": true, "with_vectors": false,
    "filter": { "must": [
      { "match": { "key": "tags", "value": "'"$TAG"'" } },
      { "key": "'"$FIELD"'", "range": { "gte": '"$SINCE"' } }
    ] }
  }'
}
SH
    echo "Created scripts/qdr_helpers.sh"
  else
    echo "scripts/qdr_helpers.sh already exists (leaving as-is)"
  fi
}

ensure_makefile_targets() {
  # Add targets only once using markers
  if ! grep -q ">>> QDRANT QUICK TARGETS (HEVA) >>>" Makefile 2>/dev/null; then
    [ -f Makefile ] && cp Makefile Makefile.bak.qdr || true
    {
      echo '# >>> QDRANT QUICK TARGETS (HEVA) >>>'
      echo 'SHELL := /usr/bin/env bash'
      echo 'export QDRANT_URL ?= http://127.0.0.1:6333'
      echo ''
      echo '.PHONY: qdr-count-oct qdr-last7 qdr-ta-since'
      echo ''
      echo 'qdr-count-oct:'
      echo '	@. scripts/qdr_helpers.sh; \'
      echo '	  START=$$(date -d '\''2025-10-01T00:00:00+08:00'\'' +%s); \'
      echo '	  END=$$(date   -d '\''2025-11-01T00:00:00+08:00'\'' +%s); \'
      echo '	  echo "Counting heva_v1.ingested_at_ts from $$START to $$END"; \'
      echo '	  qdr_count_window heva_v1 ingested_at_ts $$START $$END'
      echo ''
      echo 'qdr-last7:'
      echo '	@. scripts/qdr_helpers.sh; \'
      echo '	  SINCE=$$(( $$(date +%s) - 7*86400 )); \'
      echo '	  echo "Last 7 days (heva_docs.ingested_at_ts >= $$SINCE)"; \'
      echo '	  qdr_range heva_docs ingested_at_ts $$SINCE "" 5'
      echo ''
      echo 'qdr-ta-since:'
      echo '	@. scripts/qdr_helpers.sh; \'
      echo '	  SINCE=$$(( $$(date +%s) - 7*86400 )); \'
      echo '	  echo "THREAT_ACTOR since last 7 days (heva_docs):"; \'
      echo '	  qdr_tag_since heva_docs THREAT_ACTOR $$SINCE ingested_at_ts 20 | jq -r ''.items // [] | .[] | {source: .payload.source, tags: .payload.tags, ts: .payload.ingested_at_ts}'''
      echo '# <<< QDRANT QUICK TARGETS (HEVA) <<<' 
      echo ''
    } >> Makefile
    echo "Appended Makefile targets (backup at Makefile.bak.qdr)"
  else
    echo "Makefile already has Qdrant targets (skipping)"
  fi
}

# ----- main -----
require_repo
ensure_helpers
ensure_makefile_targets

echo "Saved helpers and Make targets."
echo "Try: make qdr-count-oct | make qdr-last7 | make qdr-ta-since"
