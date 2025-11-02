#!/usr/bin/env bash
# add_qdr_all_target.sh
# WSL-safe (no set -e). Appends a qdr-all target if not present.

MAKEFILE="Makefile"
START_MARK="### >>> HEVA ALL START >>>"
END_MARK="### <<< HEVA ALL END <<<"

if [ ! -f "$MAKEFILE" ]; then
  echo "❌ $MAKEFILE not found in $(pwd)"
  exit 1
fi

cp -f "$MAKEFILE" "${MAKEFILE}.bak.qdr_all" 2>/dev/null || true

# Strip old block (if exists)
awk -v s="$START_MARK" -v e="$END_MARK" '
  BEGIN{skip=0}
  index($0,s){skip=1; next}
  index($0,e){skip=0; next}
  !skip{print}
' "${MAKEFILE}.bak.qdr_all" > "${MAKEFILE}.tmp"

cat >> "${MAKEFILE}.tmp" <<'MAKE'
### >>> HEVA ALL START >>>
.PHONY: qdr-all
qdr-all:
	@echo "→ qdr-fix-clock"
	@$(MAKE) qdr-fix-clock || true
	@echo
	@echo "→ qdr-seed (idempotent)"
	@$(MAKE) qdr-seed || true
	@echo
	@echo "→ qdr-smoke"
	@$(MAKE) qdr-smoke || true
### <<< HEVA ALL END <<<
MAKE

mv -f "${MAKEFILE}.tmp" "${MAKEFILE}"
echo "✅ Added qdr-all target. Backup at ${MAKEFILE}.bak.qdr_all"
