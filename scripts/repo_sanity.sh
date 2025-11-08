#!/usr/bin/env bash
# WSL-safe: no set -e; tolerate missing tools

echo "== remotes ==" && git remote -v
echo "== upstream ==" && git status -sb

echo "== conflict markers =="
rg -n --hidden -g '!**/.git/**' -g '!**/.venv/**' --pcre2 '^(<<<<<<<( .*)?$|=======$|>>>>>>> .*)' . 2>/dev/null || true

echo "== lfs tracked ==" && git lfs ls-files 2>/dev/null || true

echo "== ignores check =="
git check-ignore -v legacy/data_unused/* 2>/dev/null || true

echo "== big loose files (>25MB, non-legacy) =="
find . -type f -size +25M -not -path './.git/*' -not -path './legacy/*' -print 2>/dev/null || true

echo "== dockerignore peek =="
[ -f .dockerignore ] && sed -n '1,120p' .dockerignore || echo "(no .dockerignore)"
