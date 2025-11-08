# --- filter file (overwrite) ---
cat > "$FILTER_FILE" <<'EOF'
# Include trees we want (use *** so files + subdirs match)
+ app/***
+ api/***
+ scripts/***
+ agent_b/***
+ tests/***
+ docs/HEVA_QDRANT_HELPERS.md
+ Makefile
+ docker-compose.yml
+ podman-compose.yml
+ pyproject.toml
+ requirements.txt
+ README.md
+ .env.example
+ pytest.ini
+ .github/***
+ .gitattributes
+ .ruffignore
+ .pre-commit-config.yaml

# Allow traversing directories (critical)
+ */

# Exclude junk/large artifacts
- legacy/***
- capstone_report/***
- capstone_aws_data/***
- .aider.tags.cache.v4/***
- .venv/***
- venv/***
- **/*.pyc
- **/*.pyo
- **/*.pyd
- **/*.tmp
- **/*.log
- **/*.tex
- **/*.bak
- **/*.bak_*
- **/*.orig
- **/*.rej
- **/__pycache__/***
- **/.pytest_cache/***
- **/.mypy_cache/***
- **/.ruff_cache/***
- **/.DS_Store
- **/nohup.out

# Drop corpora & notebooks
- Raw_Crawled _Data_With_LLM.json
- original_Raw_Crawled _Data_With_LLM.json
- combined.json
- ner_training.txt
- **/*.ipynb

# Default deny
- *
EOF

# --- rsync (add --delete-excluded) ---
rsync -av --dry-run \
  --filter="merge $FILTER_FILE" \
  --delete-excluded \
  ./ "$EXPORT_DIR/agent_b/"

# When happy with dry-run, do the real copy:
rsync -av \
  --filter="merge $FILTER_FILE" \
  --delete-excluded \
  ./ "$EXPORT_DIR/agent_b/"

# --- write a protective .gitignore inside export repo ---
cat > "$EXPORT_DIR/agent_b/.gitignore" <<'EOF'
# Byte-compiled / cache
__pycache__/
*.pyc
*.pyo
*.pyd
.pytest_cache/
.ruff_cache/
.mypy_cache/

# Virtual envs
.venv/
venv/

# Local env & logs
.env
.env.*
*.log
nohup.out

# OS cruft
.DS_Store
Thumbs.db
EOF

# --- essentials: accept any of these that represent Agent B entry points ---
missing=()
check_one_of() {
  # ok if at least one exists
  for f in "$@"; do [[ -f "$EXPORT_DIR/agent_b/$f" ]] && return 0; done
  return 1
}

# Must have API + one “index/ingest” entry point
required_all=(
  "api/qdrant_client.py"
  "api/search_api_rich.py"
  "scripts/chunk_and_ingest.py"
)
for f in "${required_all[@]}"; do
  [[ -f "$EXPORT_DIR/agent_b/$f" ]] || missing+=("$f")
done

# Flexible indexer location (different repos lay this out differently)
if ! check_one_of "app/indexer.py" "app/qdrant_utils.py" "scripts/chunk_and_ingest.py"; then
  missing+=("(one of) app/indexer.py | app/qdrant_utils.py | scripts/chunk_and_ingest.py")
fi

if ((${#missing[@]})); then
  echo "⚠️  Some expected files are missing:"
  printf '   - %s\n' "${missing[@]}"
  echo "→ Run: ls -l app/ api/ scripts/ to confirm actual paths, then update FILTER_FILE or the essentials list."
  read -rp "Press Enter to exit..."
  exit 1
fi

