#!/usr/bin/env bash
# add_qdr_fix_clock_target.sh
# Idempotently append a 'qdr-fix-clock' target to your Makefile.
# - WSL-safe (no 'set -e')
# - Ensures tabs are preserved in recipe lines

MAKEFILE="Makefile"
START_MARK="### >>> HEVA FIX-CLOCK START >>>"
END_MARK="### <<< HEVA FIX-CLOCK END <<<"

if [ ! -f "$MAKEFILE" ]; then
  echo "❌ $MAKEFILE not found in $(pwd)"
  exit 1
fi

cp -f "$MAKEFILE" "${MAKEFILE}.bak.fix_clock" 2>/dev/null || true

# Remove any prior block
awk -v s="$START_MARK" -v e="$END_MARK" '
  BEGIN{skip=0}
  index($0,s){skip=1; next}
  index($0,e){skip=0; next}
  !skip{print}
' "${MAKEFILE}.bak.fix_clock" > "${MAKEFILE}.tmp"

# Append a fresh block (uses inline bash to normalize mtimes & sleep)
cat >> "${MAKEFILE}.tmp" <<'MAKE'
### >>> HEVA FIX-CLOCK START >>>
.PHONY: qdr-fix-clock
qdr-fix-clock:
	@bash -c 'shopt -s nullglob; files=(Makefile *.mk); now=$$(date +%s); touched=0; \
	for f in "$${files[@]}"; do \
	  [ -e "$$f" ] || continue; \
	  if stat -c %Y "$$f" >/dev/null 2>&1; then m=$$(stat -c %Y "$$f"); else m=$$(stat -f %m "$$f"); fi; \
	  if [ -n "$$m" ] && [ "$$m" -gt "$$now" ] 2>/dev/null; then touch "$$f"; touched=$$((touched+1)); fi; \
	done; \
	sleep 1; echo "✅ qdr-fix-clock: touched $$touched file(s) & waited 1s."'
	@echo "Tip: run 'make qdr-smoke' after this."
### <<< HEVA FIX-CLOCK END <<<
MAKE

mv -f "${MAKEFILE}.tmp" "$MAKEFILE"
echo "✅ Added qdr-fix-clock to Makefile. Backup at ${MAKEFILE}.bak.fix_clock"
echo "Run: make qdr-fix-clock"
