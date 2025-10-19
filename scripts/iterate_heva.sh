#!/usr/bin/env bash
set -euo pipefail

# ==== knobs ====
MAX_ITERS="${MAX_ITERS:-3}"
AIDER_MODEL="${AIDER_MODEL:-gpt-4o-mini}"
AIDER_BIN="${AIDER_BIN:-aider}"
COMMIT_MSG_PREFIX="${COMMIT_MSG_PREFIX:-heva: auto-iteration}"
PROMPT_FILE="${PROMPT_FILE:-.aider_iter_prompt.txt}"
FILES_TO_ADD="${FILES_TO_ADD:-agentB_heva.py search_api_rich.py}"
# ==============

# 1) restart app so tests run against fresh server
scripts/restart_api.sh

# 2) initial healthcheck
if ! scripts/healthcheck.sh; then
  echo "[iterate] WARN: healthcheck failed before iteration (this is okay; we will try to fix)."
fi

# 3) prepare aider prompt (single source of truth)
cat > "$PROMPT_FILE" <<'TXT'
Refactor Agent B (HEVA) for stability and test readiness:
- Keep API signatures unchanged.
- Ensure /health and /search are reliable (no crashes on empty or short queries).
- Add robust error handling and structured logging around Qdrant calls.
- Improve type hints and docstrings (no behavior changes unless fixing bugs).
- If you propose changes across functions, keep diffs small and cohesive.

Stop when no further improvements apply.
TXT

# 4) iteration loop
for i in $(seq 1 "$MAX_ITERS"); do
  echo "======================"
  echo "[iterate] Pass $i / $MAX_ITERS"
  echo "======================"

  # Aider run: add files, apply prompt, auto-commit
  # Notes:
  #  - --yes answers yes to apply patches
  #  - we send commands through STDIN to avoid TTY interactivity
  {
    for f in $FILES_TO_ADD; do
      echo "add $f"
    done
    echo "Use the following instructions exactly:"
    echo
    cat "$PROMPT_FILE"
    echo
  } | "${AIDER_BIN}" \
        --model "${AIDER_MODEL}" \
        --auto-commit \
        --yes

  # Restart app to pick up changes
  scripts/restart_api.sh

  # Test after each pass
  if scripts/healthcheck.sh; then
    echo "[iterate] ✅ Tests passed after pass $i — stopping early."
    exit 0
  else
    echo "[iterate] ❌ Tests failed after pass $i — continuing."
  fi
done

echo "[iterate] Reached MAX_ITERS=${MAX_ITERS} with failing tests."
exit 1

