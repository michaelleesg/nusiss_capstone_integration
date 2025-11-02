#!/usr/bin/env bash
# add_heva_param_targets_clean.sh
# WSL-safe (no set -euo); idempotent; preserves tabs in Makefile recipes.

MAKEFILE="Makefile"
START_MARK="### >>> HEVA PARAM START >>>"
END_MARK="### <<< HEVA PARAM END <<<"

if [ ! -f "$MAKEFILE" ]; then
  echo "❌ $MAKEFILE not found in $(pwd)"
  exit 1
fi

# Backup
cp -f "$MAKEFILE" "${MAKEFILE}.bak.heva_param_clean" 2>/dev/null || true

# Remove any prior PARAM block if present
awk -v s="$START_MARK" -v e="$END_MARK" '
  BEGIN{skip=0}
  index($0,s){skip=1; next}
  index($0,e){skip=0; next}
  !skip{print}
' "${MAKEFILE}.bak.heva_param_clean" > "${MAKEFILE}.tmp"

# Append fresh block (NOTE: recipe lines must start with a real TAB)
cat >> "${MAKEFILE}.tmp" <<'MAKE'
### >>> HEVA PARAM START >>>
.PHONY: qdr-since
qdr-since:
	@DAYS=$${DAYS:-7}; TAG=$${TAG:-THREAT_ACTOR}; COL=$${COL:-heva_docs}; \
	  SINCE=$$(( $$(date +%s) - $$DAYS*86400 )); \
	  echo "Query: collection=$$COL tag=$$TAG since=$$SINCE ($$DAYS d)"; \
	  jq -n --arg tag "$$TAG" --argjson since $$SINCE '{limit:200, with_payload:true, with_vectors:false, filter:{must:[{key:"tags", match:{value:$tag}}, {key:"ingested_at_ts", range:{gte:$since}}]}}' | \
	  curl -sS -X POST "$(QDR)/collections/$$COL/points/scroll" -H 'Content-Type: application/json' -d @- | \
	  jq -c '{count: ((.result.points // [])|length), items: ((.result.points // [])|map({id, payload}))}'
### <<< HEVA PARAM END <<<
MAKE

mv "${MAKEFILE}.tmp" "${MAKEFILE}"
echo "✅ Added qdr-since target (clean). Backup at ${MAKEFILE}.bak.heva_param_clean"
echo "Examples:"
echo "  make qdr-since                 # defaults: DAYS=7 TAG=THREAT_ACTOR COL=heva_docs"
echo "  make qdr-since DAYS=30"
echo '  make qdr-since TAG="INDICATOR"'
echo "  make qdr-since COL=heva_docs QDR=http://127.0.0.1:6333"
