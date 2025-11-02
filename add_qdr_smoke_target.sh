#!/usr/bin/env bash
# add_qdr_smoke_target.sh
# WSL-safe (no set -e); idempotent; preserves tabs in Makefile recipes.

MAKEFILE="Makefile"
START_MARK="### >>> HEVA SMOKE START >>>"
END_MARK="### <<< HEVA SMOKE END <<<"

if [ ! -f "$MAKEFILE" ]; then
  echo "❌ $MAKEFILE not found in $(pwd)"
  exit 1
fi

cp -f "$MAKEFILE" "${MAKEFILE}.bak.qdr_smoke" 2>/dev/null || true

# Remove any prior SMOKE block if present
awk -v s="$START_MARK" -v e="$END_MARK" '
  BEGIN{skip=0}
  index($0,s){skip=1; next}
  index($0,e){skip=0; next}
  !skip{print}
' "${MAKEFILE}.bak.qdr_smoke" > "${MAKEFILE}.tmp"

# Append fresh block (NOTE: lines under target must start with a real TAB)
cat >> "${MAKEFILE}.tmp" <<'MAKE'
### >>> HEVA SMOKE START >>>
.PHONY: qdr-smoke
qdr-smoke:
	@echo "— qdr-ping —";     $(MAKE) qdr-ping || true
	@echo; echo "— count-oct —"; $(MAKE) qdr-count-oct || true
	@echo; echo "— last7 —";     $(MAKE) qdr-last7 || true
	@echo; echo "— ta-since —";  $(MAKE) qdr-ta-since || true
	@echo; read -rp "Done. Press Enter to close..." _
### <<< HEVA SMOKE END <<<
MAKE

mv -f "${MAKEFILE}.tmp" "$MAKEFILE"
echo "✅ Added qdr-smoke to Makefile. Backup at ${MAKEFILE}.bak.qdr_smoke"
echo "Run: make qdr-smoke"
