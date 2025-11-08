# Contributing Guide

Welcome! This repo uses a **two‑remote** flow and a few guardrails so we keep history clean and CI happy.  
If you follow the quickstart below you’ll be in great shape.

---

## TL;DR (Quickstart)

```bash
# 0) Make sure your remotes are set
git remote -v
# Should show:
# integration  https://github.com/michaelleesg/nusiss_capstone_integration.git
# test         https://github.com/michaelleesg/nus-iss-test.git

# 1) Keep your working tree clean
git fetch --all --prune
git status -sb

# 2) Rebase on the 'test' default branch before pushing
git fetch test
git rebase $(git ls-remote --symref test HEAD | awk '/^ref:/ {sub("refs/heads/","",$2); print $2; exit}')
# resolve conflicts if any → git add -A && git rebase --continue

# 3) Push to both remotes
for R in integration test; do
  RBR=$(git ls-remote --symref "$R" HEAD 2>/dev/null | awk '/^ref:/ {sub("refs/heads/","",$2); print $2; exit}')
  [ -z "$RBR" ] && RBR=$(git rev-parse --abbrev-ref HEAD)
  git push -u "$R" HEAD:"$RBR"
done
```

---

## Branching & Remotes

- **Default branch** is typically `main`. We detect the remote default branch dynamically:
  ```bash
  git ls-remote --symref integration HEAD
  git ls-remote --symref test HEAD
  ```
- Remotes in this repo:
  - `integration` → `nusiss_capstone_integration` (primary integration surface)
  - `test` → `nus-iss-test` (kept in sync; **do not disable** CI workflows there)

If a remote is missing, add it once:
```bash
git remote add integration https://github.com/michaelleesg/nusiss_capstone_integration.git
git remote add test        https://github.com/michaelleesg/nus-iss-test.git
```

---

## Pre‑commit Checklist

- ✅ Working tree clean (`git status -sb`).
- ✅ No conflict markers:
  ```bash
  rg -n --hidden -g '!**/.git/**' -g '!**/.venv/**' --pcre2 '^(<<<<<<<( .*)?$|=======$|>>>>>>> .*)' .
  ```
- ✅ No accidental large files (>25 MB) outside `legacy/`:
  ```bash
  find . -type f -size +25M -not -path './.git/*' -not -path './legacy/*' -print
  ```
- ✅ Code style (if Python files changed):
  ```bash
  ruff check . && black --check . && mypy || true
  pytest -q || true   # if tests exist
  ```

---

## Repo Sanity Helpers (drop into your shell)

```bash
repo_sanity() {
  echo "== remotes ==" && git remote -v
  echo "== upstream ==" && git status -sb
  echo "== conflict markers ==" && rg -n --hidden -g '!**/.git/**' -g '!**/.venv/**' --pcre2 '^(<<<<<<<( .*)?$|=======$|>>>>>>> .*)' . || true
  echo "== lfs tracked ==" && git lfs ls-files || true
  echo "== ignores check ==" && git check-ignore -v legacy/data_unused/* || true
  echo "== big loose files (>25MB, non-legacy) ==" &&     find . -type f -size +25M -not -path './.git/*' -not -path './legacy/*' -print || true
  echo "== dockerignore peek ==" && tail -n +1 .dockerignore | sed -n '1,120p' || true
}

scan_conflicts() {
  local RG='^(<<<<<<<( .*)?$|=======$|>>>>>>> .*)'
  rg -n --hidden     -g '!**/.git/**' -g '!**/.venv/**' -g '!**/*.bak'     --pcre2 "$RG" .
}
```

---

## Large Files & LFS Policy

- **Current state**: No active LFS‑tracked runtime assets. Legacy data were moved under `legacy/data_unused/` and are **ignored**.
- **Do not re‑add** LFS tracking for:
  - `legacy/data_unused/*`
  - `combined.json`
  - `ner_training.txt`
- If you must store large data, prefer:
  - External storage (artifact store, object storage, or a dedicated dataset repo).
  - Small sampled fixtures for tests (≤1–5 MB) checked into `tests/fixtures/`.

---

## Ignore Rules (important)

Baseline entries (already committed):
```
**/.venv/
**/__pycache__/
.pytest_cache/
.qdrant/
legacy/
legacy/data_unused/
```
> Keep these; don’t commit virtualenvs, caches, Qdrant state, or legacy datasets.

---

## Commit Message Style

Use Conventional Commits where possible:
- `feat:` new user‑facing capability
- `fix:` bug fix
- `docs:` documentation only
- `chore:` repo upkeep (ignores, LFS, renames)
- `refactor:` internal changes, no behavior change
- `ci:` workflows, actions
- `test:` tests

Examples:
```
feat(ingest): add published_at passthrough to Qdrant payload
chore(lfs): stop tracking legacy data; ignore legacy/data_unused
docs: add CONTRIBUTING with two-remote flow
```

---

## Rebase Policy (keep history linear)

1) Make sure you’re on your working branch (often `main`):
```bash
git rev-parse --abbrev-ref HEAD
```

2) Rebase on the remote’s default branch (example with `test`):
```bash
git fetch test
git rebase $(git ls-remote --symref test HEAD | awk '/^ref:/ {sub("refs/heads/","",$2); print $2; exit}')
# Resolve conflicts → git add -A && git rebase --continue
```

3) Push:
```bash
git push -u test HEAD:$(git ls-remote --symref test HEAD | awk '/^ref:/ {sub("refs/heads/","",$2); print $2; exit}')
git push -u integration HEAD:$(git ls-remote --symref integration HEAD | awk '/^ref:/ {sub("refs/heads/","",$2); print $2; exit}')
```

> If a push is rejected for non‑fast‑forward: re‑fetch and rebase again. Prefer **rebase** over merge to keep a clean linear history.

---

## Two‑Remote Push Helper

```bash
push_both() {
  for R in integration test; do
    if git remote get-url "$R" >/dev/null 2>&1; then
      RBR=$(git ls-remote --symref "$R" HEAD 2>/dev/null | awk '/^ref:/ {sub("refs/heads/","",$2); print $2; exit}')
      [ -z "$RBR" ] && RBR=$(git rev-parse --abbrev-ref HEAD)
      git push -u "$R" HEAD:"$RBR" || true
    fi
  done
}
```

---

## WSL‑Safe Bash & Makefile Notes

- Avoid abrupt `exit` statements in scripts; they can close WSL terminals unexpectedly.
- Prefer **not** to use `set -e` globally without traps; guard failing commands with `|| true` where appropriate.
- **Makefiles**:
  - Use a **real TAB** at the start of each recipe line (not `\t`).
  - Escape dollars as `$$` inside recipes.
  - If you need defaults, prefer Make’s `?=` over shell defaulting to avoid `$$`→PID surprises.
  - When using `jq` in single quotes, escape inner single quotes as `'''`.

---

## CI / Workflows

- **Do not disable** the GitHub Actions workflow named **“Update Cybersage Primary Su…”** in `michaelleesg/nus-iss-test`. A teammate relies on it for submodule updates into the main repo.

---

## Dev Environment (Python)

- Python **3.11** is the house version.
- Recommended:
  ```bash
  python -m venv .venv && source .venv/bin/activate
  pip install -U pip
  # If using pyproject:
  pip install -e . || pip install -r requirements.txt || true
  # Linters/tests:
  pip install ruff black mypy pytest
  ```

---

## Questions

Open a GitHub Discussion/Issue or ping the maintainers via the org channel.
