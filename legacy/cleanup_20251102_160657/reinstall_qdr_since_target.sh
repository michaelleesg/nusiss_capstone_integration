#!/usr/bin/env bash
# reinstall_qdr_since_target.sh — WSL-safe; idempotent; real TAB; Make ?= defaults; $(VAR) pass-through.
set +e

MAKEFILE="Makefile"
START="### >>> HEVA PARAM START >>>"
END="### <<< HEVA PARAM END <<<"

[ -f "$MAKEFILE" ] || { echo "❌ $MAKEFILE not found"; exit 1; }

# Ensure Make defaults (top of file, once)
tmp="$(mktemp)"; inserted=0
awk -v ins=0 '
  NR==1 { print; next }
  ins==0 && $0 !~ /^[[:space:]]*(#|$)/ {
    print "QDR ?= http://127.0.0.1:6333"
    print "COL ?= heva_docs"
    print "TAG ?= THREAT_ACTOR"
    print "DAYS ?= 7"
    ins=1
  }
  { print }
' "$MAKEFILE" > "$tmp" && mv "$tmp" "$MAKEFILE"

cp -f "$MAKEFILE" "${MAKEFILE}.bak.reinstall_qdr_since" 2>/dev/null || true

# Remove any existing block
awk -v s="$START" -v e="$END" '
  BEGIN{skip=0}
  index($0,s){skip=1; next}
  index($0,e){skip=0; next}
  !skip{print}
' "${MAKEFILE}.bak.reinstall_qdr_since" > "${MAKEFILE}.tmp"

# Append clean block (REAL TAB on recipe line)
{
  printf "%s\n" "$START"
  printf "%s\n" ".PHONY: qdr-since qdr-since-help"
  printf "%s\n" "qdr-since:"
  printf "\t%s\n" '@bash scripts/qdr_since.sh "$(QDR)" "$(COL)" "$(TAG)" "$(DAYS)"'
  printf "%s\n" "qdr-since-help:"
  printf "\t%s\n" '@echo "Usage: make qdr-since [QDR=…] [COL=…] [TAG=…] [DAYS=…]"; echo "Defaults via Make: QDR=$(QDR) COL=$(COL) TAG=$(TAG) DAYS=$(DAYS)"'
  printf "%s\n" "$END"
} >> "${MAKEFILE}.tmp"

mv "${MAKEFILE}.tmp" "$MAKEFILE"
echo "✅ Reinstalled qdr-since target. Backup at ${MAKEFILE}.bak.reinstall_qdr_since"

echo "Sanity:"
echo "  nl -ba Makefile | sed -n '/$START/,/$END/p'   # check REAL TAB on recipe"
echo "  make -n qdr-since                           # dry-run"

