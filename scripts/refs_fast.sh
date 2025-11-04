#!/usr/bin/env bash
set +e
ROOT="${ROOT:-/home/mike/capstone_win}"
OUT="${OUT:-$PWD/_inventory}"
PYTHON="${PYTHON:-python3}"
echo "[refs_fast] root=$ROOT out=$OUT"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOL="$SCRIPT_DIR/../refs_fast.py"
if [[ ! -f "$TOOL" ]]; then
  echo "[refs_fast] missing ../refs_fast.py; trying PATH"
  TOOL="refs_fast.py"
fi
"$PYTHON" "$TOOL" --root "$ROOT" --out "$OUT"
RC=$?
echo "[refs_fast] exit=$RC"
exit $RC
