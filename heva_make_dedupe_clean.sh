#!/usr/bin/env bash
# heva_make_dedupe_clean.sh
# WSL-safe: no `set -euo`. Keeps the *newest* HEVA blocks and removes older duplicates.
# Also normalizes tabs in recipes and trims trailing whitespace.
# Backs up Makefile to Makefile.bak.heva_dedupe_clean

MAKEFILE="Makefile"
BACKUP="${MAKEFILE}.bak.heva_dedupe_clean"

if [ ! -f "$MAKEFILE" ]; then
  echo "❌ $MAKEFILE not found in $(pwd)"
  read -rp "Press Enter to exit..."
  exit 0
fi

cp -f "$MAKEFILE" "$BACKUP" 2>/dev/null || true

# 1) Keep only the newest of each HEVA block (TARGETS & EXTRAS)
awk '
  BEGIN{
    s1="### >>> HEVA QDRANT TARGETS >>>"
    e1="### <<< HEVA QDRANT TARGETS <<<"
    s2="### >>> HEVA EXTRAS START >>>"
    e2="### <<< HEVA EXTRAS END <<<"
  }
  { buf[NR]=$0 }
  index($0,s1){ S1[++c1]=NR }
  index($0,e1){ E1[c1]=NR }
  index($0,s2){ S2[++c2]=NR }
  index($0,e2){ E2[c2]=NR }
  END{
    # helper to blank earlier ranges
    for (i=1; i<c1; i++) for (ln=S1[i]; ln<=E1[i]; ln++) buf[ln]=""
    for (i=1; i<c2; i++) for (ln=S2[i]; ln<=E2[i]; ln++) buf[ln]=""
    for (i=1;i<=NR;i++) print buf[i]
  }
' "$BACKUP" > "${MAKEFILE}.tmp1"

# 2) Normalize: ensure recipes use TAB (Make requires literal tabs)
#    Convert leading 2+ spaces before a recipe command into a single TAB.
#    Heuristic: lines that start with 2+ spaces then a non-space char.
python3 - <<'PY' "${MAKEFILE}.tmp1" > "${MAKEFILE}.tmp2"
import re, sys
inp = sys.argv[1]
out_lines = []
with open(inp, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        # Replace leading 2+ spaces with a single tab for recipe commands
        out_lines.append(re.sub(r'^( {2,})(?=\S)', '\t', line.rstrip()) + '\n')
sys.stdout.writelines(out_lines)
PY

# 3) Trim trailing whitespace-only lines and collapse >2 blank lines to 1
awk '
  { sub(/[ \t\r]+$/, "", $0) }     # trim trailing spaces/tabs
  { if ($0 == "") { blank++ } else { blank=0 } }
  { if (blank <= 1) print }
' "${MAKEFILE}.tmp2" > "${MAKEFILE}.tmp3"

mv -f "${MAKEFILE}.tmp3" "${MAKEFILE}"
rm -f "${MAKEFILE}.tmp1" "${MAKEFILE}.tmp2"

echo "OK: Makefile deduped/cleaned. Backup at $BACKUP"
echo "Run: make qdr-ping | make qdr-count-oct | make qdr-last7 | make qdr-ta-since"
read -rp "Press Enter to exit..."
