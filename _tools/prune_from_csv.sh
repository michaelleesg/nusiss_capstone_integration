#!/usr/bin/env bash
set +e
ROOT="${ROOT:-/home/mike/capstone_win}"
CSV="${1:-_inventory/to_remove.csv}"
DRY="${DRY_RUN:-1}"  # 1=dry-run, 0=real
echo "[prune] root=$ROOT  csv=$CSV  dry=$DRY"
[ -f "$CSV" ] || { echo "[err] CSV not found: $CSV"; exit 2; }

# Guard against accidental removals
declare -A GUARD
for p in \
  ".git" ".git/**" "_tools/prune_from_csv.sh" "scripts/list_files_usage.sh" "scan_usage.py" \
  "refs_fast.py" "scripts/refs_fast.sh" "_inventory/to_remove.csv"
do GUARD["$p"]=1; done

tail -n +2 "$CSV" | while IFS=, read -r rel _; do
  rel="${rel%%$'\r'}"; [ -z "$rel" ] && continue
  # Skip guarded paths
  if [[ -n "${GUARD[$rel]}" ]]; then echo "[skip] $rel (guarded)"; continue; fi
  abs="$ROOT/$rel"
  if git -C "$ROOT" ls-files --error-unmatch -- "$rel" >/dev/null 2>&1; then
    echo "[git rm] $rel"
    [ "$DRY" = "1" ] || git -C "$ROOT" rm -f -- "$rel"
  else
    echo "[rm] $rel"
    [ "$DRY" = "1" ] || rm -rf -- "$abs"
  fi
done
echo "[done] Set DRY_RUN=0 to actually delete."
