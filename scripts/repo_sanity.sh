# overwrite: scripts/repo_sanity.sh
#!/usr/bin/env bash
# WSL-safe: don't exit on errors; tolerate missing tools

echo "== remotes ==" && git remote -v
echo "== upstream ==" && git status -sb

echo "== conflict markers =="
# exclude .git and ANY nested .venv dirs
rg -n --hidden \
  -g '!**/.git/**' \
  -g '!**/.venv/**' \
  --pcre2 '^(<<<<<<<( .*)?$|=======$|>>>>>>> .*)' . 2>/dev/null || true

echo "== lfs tracked ==" && git lfs ls-files 2>/dev/null || true

echo "== ignores check (.venv + legacy) =="
# show whether .venv/* and legacy/data_unused/* are ignored
git check-ignore -v **/.venv/** legacy/data_unused/* 2>/dev/null || true

echo "== big loose files (>25MB, non-legacy, non-.venv) =="
# skip .git, legacy, and ANY nested .venv dirs
find . -type f -size +25M \
  -not -path './.git/*' \
  -not -path './legacy/*' \
  -not -path '*/.venv/*' \
  -print 2>/dev/null || true

echo "== dockerignore peek =="
[ -f .dockerignore ] && sed -n '1,120p' .dockerignore || echo "(no .dockerignore)"
