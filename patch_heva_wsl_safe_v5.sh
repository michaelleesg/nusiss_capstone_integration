#!/usr/bin/env bash
# patch_heva_wsl_safe_v5.sh
# WSL-safe Makefile patcher for HEVA Qdrant helpers.
# - Normalizes CRLF to LF
# - Removes all previous HEVA blocks
# - Appends clean targets with correct here-doc EOF markers
# - Uses /bin/bash, avoids set -euo in recipes, and avoids fragile single quotes inside JSON

set -u  # keep -u for the patcher itself (not in Makefile recipes)

MAKEFILE="Makefile"
START_MARK="### >>> HEVA QDRANT TARGETS >>>"
END_MARK="### <<< HEVA QDRANT TARGETS <<<"

if [ ! -f "$MAKEFILE" ]; then
  echo "❌ $MAKEFILE not found in $(pwd)"
  exit 1
fi

# 0) Normalize CRLF → LF (in-place)
#    Use python if available for portability; fall back to sed.
if command -v python3 >/dev/null 2>&1; then
  python3 - "$MAKEFILE" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1])
p.write_bytes(p.read_bytes().replace(b'\r\n', b'\n'))
PY
else
  sed -i 's/\r$//' "$MAKEFILE" 2>/dev/null || true
fi

cp -f "$MAKEFILE" "${MAKEFILE}.bak.heva_wsl_v5"

# 1) Strip all existing HEVA blocks (between START_MARK and END_MARK, inclusive)
awk -v s="$START_MARK" -v e="$END_MARK" '
  BEGIN {skip=0}
  index($0, s) { skip=1; next }
  index($0, e) { skip=0; next }
  !skip { print }
' "${MAKEFILE}.bak.heva_wsl_v5" > "${MAKEFILE}.tmp"

# 2) Append clean block (we write with printf to guarantee recipe tabs)
{
  echo ""
  echo "$START_MARK"
  echo "SHELL := /bin/bash"
  echo "QDR ?= http://127.0.0.1:6333"
  echo ""

  # qdr-ping
  echo "qdr-ping:"
  printf '\t@echo "Pinging $(QDR)/collections ..."\n'
  printf '\t@curl -sS "$(QDR)/collections" | jq \x27.result.collections | length\x27 || true\n'
  echo ""

  # qdr-count-oct
  echo "qdr-count-oct:"
  printf '\t@START=$$(date -d \x272025-10-01T00:00:00+08:00\x27 +%%s); \\\n'
  printf '\tEND=$$(date   -d \x272025-11-01T00:00:00+08:00\x27 +%%s); \\\n'
  printf '\techo "Counting heva_v1.ingested_at_ts from $$START to $$END"; \\\n'
  printf '\tcat <<\x27EOF\x27 | jq --argjson start $$START --argjson end $$END \x27.filter.must[0].range.gte=$start | .filter.must[0].range.lte=$end\x27 | \\\n'
  printf '\tcurl -sS -X POST "$(QDR)/collections/heva_v1/points/count" -H \x27Content-Type: application/json\x27 -d @- | jq \x27.result\x27\n'
  printf '{\n'
  printf '  "with_payload": false,\n'
  printf '  "with_vectors": false,\n'
  printf '  "filter": { "must": [ { "key": "ingested_at_ts", "range": { "gte": 0, "lte": 0 } } ] },\n'
  printf '  "limit": 1\n'
  printf '}\n'
  echo "EOF"
  echo ""

  # qdr-last7
  echo "qdr-last7:"
  printf '\t@SINCE=$$(( $$(date +%%s) - 7*86400 )); \\\n'
  printf '\techo "Last 7 days (heva_docs.ingested_at_ts >= $$SINCE)"; \\\n'
  printf '\tcat <<\x27EOF\x27 | jq --argjson since $$SINCE \x27.filter.must[0].range.gte=$since\x27 | \\\n'
  printf '\tcurl -sS -X POST "$(QDR)/collections/heva_docs/points/scroll" -H \x27Content-Type: application/json\x27 -d @- | \\\n'
  printf '\tjq -c \x27{count: ((.result.points // [])|length), items: ((.result.points // [])|map({id, payload}))}\x27\n'
  printf '{\n'
  printf '  "limit": 200,\n'
  printf '  "with_payload": true,\n'
  printf '  "with_vectors": false,\n'
  printf '  "filter": { "must": [ { "key": "ingested_at_ts", "range": { "gte": 0 } } ] }\n'
  printf '}\n'
  echo "EOF"
  echo ""

  # qdr-ta-since
  echo "qdr-ta-since:"
  printf '\t@SINCE=$$(( $$(date +%%s) - 7*86400 )); \\\n'
  printf '\techo "THREAT_ACTOR since last 7 days (heva_docs)"; \\\n'
  printf '\tcat <<\x27EOF\x27 | jq --argjson since $$SINCE \x27.filter.must[1].range.gte=$since\x27 | \\\n'
  printf '\tcurl -sS -X POST "$(QDR)/collections/heva_docs/points/scroll" -H \x27Content-Type: application/json\x27 -d @- | \\\n'
  printf '\tjq -c \x27{count: ((.result.points // [])|length), items: ((.result.points // [])|map({id, payload}))}\x27\n'
  printf '{\n'
  printf '  "limit": 200,\n'
  printf '  "with_payload": true,\n'
  printf '  "with_vectors": false,\n'
  printf '  "filter": { "must": [\n'
  printf '    { "match": { "key": "tags", "value": "THREAT_ACTOR" } },\n'
  printf '    { "key": "ingested_at_ts", "range": { "gte": 0 } }\n'
  printf '  ] }\n'
  printf '}\n'
  echo "EOF"
  echo ""

  echo "$END_MARK"
} >> "${MAKEFILE}.tmp"

mv "${MAKEFILE}.tmp" "${MAKEFILE}"
echo "OK: Makefile updated (HEVA WSL-safe v5). Backup at ${MAKEFILE}.bak.heva_wsl_v5"
echo "Try: make qdr-ping | make qdr-count-oct | make qdr-last7 | make qdr-ta-since"
