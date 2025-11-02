#!/usr/bin/env bash
# qdr_since.sh
# WSL-safe runner (no 'set -euo'); interactive prompt at end to avoid closing WSL windows.
# Usage: bash qdr_since.sh [QDR] [COL] [TAG] [DAYS]
# Defaults: QDR=http://127.0.0.1:6333 COL=heva_docs TAG=THREAT_ACTOR DAYS=7
# Takes care of: (1) real tabs live in Makefile target (handled by the patcher),
# (2) keep single-quoted jq program intact to avoid 'unexpected EOF while looking for matching ''.

QDR="${1:-http://127.0.0.1:6333}"
COL="${2:-heva_docs}"
TAG="${3:-THREAT_ACTOR}"
DAYS="${4:-7}"

SINCE=$(( $(date +%s) - DAYS*86400 ))

echo "Query: collection=${COL} tag=${TAG} since=${SINCE} (${DAYS} d)"
jq -n --arg tag "${TAG}" --argjson since "${SINCE}" '{
  limit: 200, with_payload: true, with_vectors: false,
  filter: { must: [
    { key: "tags",           match: { value: $tag } },
    { key: "ingested_at_ts", range: { gte: $since } }
  ] }
}' | curl -sS -X POST "${QDR}/collections/${COL}/points/scroll"   -H 'Content-Type: application/json' -d @- | jq -c '{count: ((.result.points // [])|length), items: ((.result.points // [])|map({id, payload}))}'

read -rp "Press Enter to exit..."
