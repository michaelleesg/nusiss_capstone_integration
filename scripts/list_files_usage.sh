#!/usr/bin/env bash
set +e
ROOT="${ROOT:-/home/mike/capstone_win}"
INVDIR="${INVDIR:-$PWD/_inventory}"
PYTHON="${PYTHON:-python3}"

RESOLVED="$ROOT"
if command -v readlink >/dev/null 2>&1; then
  R="$(readlink -f -- "$ROOT" 2>/dev/null)"
  if [[ -n "$R" ]]; then RESOLVED="$R"; fi
fi

echo "[list] Supplied root : $ROOT"
echo "[list] Resolved root : $RESOLVED"
if [[ "$ROOT" != "$RESOLVED" ]]; then
  echo "[list] Note: root is a symlink; scanning resolved target."
fi
echo "[list] Out           : $INVDIR"
mkdir -p "$INVDIR"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCANNER="$SCRIPT_DIR/../scan_usage.py"
if [[ ! -f "$SCANNER" ]]; then
  echo "[list] scanner not found next to scripts; trying PATH fallback"
  SCANNER="scan_usage.py"
fi

"$PYTHON" "$SCANNER" --root "$ROOT" --out "$INVDIR"
RC=$?
echo "[list] exit code: $RC"
echo
echo "[next] _inventory ready."
if [[ -z "$NO_PAUSE" ]]; then
  read -rp "Press Enter to close..."
fi
exit $RC
