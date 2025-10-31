qdr_scroll() {
  local COL="$1" JSON="$2"
  curl -s -X POST "${QDRANT_URL:-http://127.0.0.1:6333}/collections/$COL/points/scroll" \
    -H 'Content-Type: application/json' -d "$JSON" |
  jq 'def brief: {id, payload}; .result.points as $p | {count: ($p|length), items: ($p|map(brief))}'
}
qdr_range() {
  local COL="$1" FIELD="$2" SINCE="$3" UNTIL="${4:-}" LIMIT="${5:-5}"
  local RANGE='"gte":'"$SINCE"; [[ -n "$UNTIL" ]] && RANGE="$RANGE, \"lt\": $UNTIL"
  qdr_scroll "$COL" '{
    "limit": '"$LIMIT"', "with_payload": true, "with_vectors": false,
    "filter": { "must": [ { "key": "'"$FIELD"'", "range": { '"$RANGE"' } } ] }
  }'
}
qdr_count_window() {
  local COL="$1" FIELD="$2" START="$3" END="$4"
  curl -s -X POST "${QDRANT_URL:-http://127.0.0.1:6333}/collections/$COL/points/count" \
    -H 'Content-Type: application/json' \
    -d '{ "exact": true, "filter": { "must": [ { "key": "'"$FIELD"'", "range": { "gte": '"$START"', "lt": '"$END"' } } ] } }' |
  jq -r '.result.count // 0'
}
qdr_tag_since() {
  local COL="$1" TAG="$2" SINCE="$3" FIELD="${4:-ingested_at_ts}" LIMIT="${5:-5}"
  qdr_scroll "$COL" '{
    "limit": '"$LIMIT"', "with_payload": true, "with_vectors": false,
    "filter": { "must": [
      { "match": { "key": "tags", "value": "'"$TAG"'" } },
      { "key": "'"$FIELD"'", "range": { "gte": '"$SINCE"' } }
    ] }
  }'
}
