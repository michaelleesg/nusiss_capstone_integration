\
    #!/usr/bin/env bash
    # Safe HEVA Makefile patcher (final jq quoting fix)
    # - Dedup any previous "HEVA QDRANT TARGETS" blocks
    # - Append a clean block with single-line jq programs (no backslashes)
    # - Null-safe handling for empty result sets
    # - Avoids subshell traps that could close WSL terminals
    #
    # Usage:
    #   chmod +x fix_heva_targets_patch.sh
    #   ./fix_heva_targets_patch.sh
    #   make qdr-count-oct | make qdr-last7 | make qdr-ta-since

    set -euo pipefail

    MAKEFILE="Makefile"
    START_MARK="### >>> HEVA QDRANT TARGETS >>>"
    END_MARK="### <<< HEVA QDRANT TARGETS <<<"

    if [[ ! -f "$MAKEFILE" ]]; then
      echo "❌ $MAKEFILE not found in $(pwd)"
      exit 1
    fi

    cp -f "$MAKEFILE" "${MAKEFILE}.bak.heva_patch"

    # 1) Strip ALL existing HEVA blocks
    awk -v s="$START_MARK" -v e="$END_MARK" '
      BEGIN{skip=0}
      index($0,s){skip=1; next}
      index($0,e){skip=0; next}
      !skip{print}
    ' "${MAKEFILE}.bak.heva_patch" > "${MAKEFILE}.tmp"

    # 2) Append a clean HEVA block (no jq line-continuations)
    cat >> "${MAKEFILE}.tmp" <<'MAKE'
    ### >>> HEVA QDRANT TARGETS >>>
    SHELL := /bin/bash
    QDR ?= http://127.0.0.1:6333

    # Count heva_v1.ingested_at_ts in Oct 2025 (SGT window)
    qdr-count-oct:
    	@START=$$(date -d '2025-10-01T00:00:00+08:00' +%s); \
    	  END=$$(date -d '2025-11-01T00:00:00+08:00' +%s); \
    	  echo "Counting heva_v1.ingested_at_ts from $$START to $$END"; \
    	  curl -s -X POST "$$QDR/collections/heva_v1/points/count" \
    	    -H 'Content-Type: application/json' \
    	    -d "$$(printf '%s' '{\"exact\":true,\"filter\":{\"must\":[{\"key\":\"ingested_at_ts\",\"range\":{\"gte\":'\"$$START\"',\"lt\":'\"$$END\"'}}]}}')" \
    	  | jq -r '.result.count // 0'

    # Last 7 days by ingested_at_ts from heva_docs
    qdr-last7:
    	@SINCE=$$(( $$(date +%s) - 7*86400 )); \
    	  echo "Last 7 days (heva_docs.ingested_at_ts >= $$SINCE)"; \
    	  curl -s -X POST "$$QDR/collections/heva_docs/points/scroll" \
    	    -H 'Content-Type: application/json' \
    	    -d "$$(printf '%s' '{\"limit\":50,\"with_payload\":true,\"with_vectors\":false,\"filter\":{\"must\":[{\"key\":\"ingested_at_ts\",\"range\":{\"gte\":'\"$$SINCE\"'}}]}}')" \
    	  | jq 'def brief: {id, payload}; (.result.points // []) as $$p | {count: ($$p|length), items: ($$p|map(brief))}'

    # THREAT_ACTOR points since last 7 days (null-safe)
    qdr-ta-since:
    	@SINCE=$$(( $$(date +%s) - 7*86400 )); \
    	  echo "THREAT_ACTOR since last 7 days (heva_docs):"; \
    	  curl -s -X POST "$$QDR/collections/heva_docs/points/scroll" \
    	    -H 'Content-Type: application/json' \
    	    -d "$$(printf '%s' '{\"limit\":50,\"with_payload\":true,\"with_vectors\":false,\"filter\":{\"must\":[{\"match\":{\"key\":\"tags\",\"value\":\"THREAT_ACTOR\"}},{\"key\":\"ingested_at_ts\",\"range\":{\"gte\":'\"$$SINCE\"'}}]}}')" \
    	  | jq '(.result.points // []) | map({source: (.payload.source // null), tags: (.payload.tags // []), ingested_at_ts: (.payload.ingested_at_ts // null)})'
    ### <<< HEVA QDRANT TARGETS <<<
    MAKE

    mv "${MAKEFILE}.tmp" "$MAKEFILE"

    echo "✅ Makefile patched. Backup at ${MAKEFILE}.bak.heva_patch"
    echo "Try:"
    echo "  make qdr-count-oct"
    echo "  make qdr-last7"
    echo "  make qdr-ta-since"
