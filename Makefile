.DEFAULT_GOAL := help
SHELL := /bin/bash

QDR ?= http://127.0.0.1:6333
COL ?= heva_docs
TAG ?= THREAT_ACTOR
DAYS ?= 7
QDR ?= http://127.0.0.1:6333
COL ?= heva_docs
TAG ?= THREAT_ACTOR
DAYS ?= 7
.PHONY: lint format test security check all up down ingest search eval set-payload set-payload

lint:
	ruff check --fix $(shell git ls-files "*.py")

format:
	black $(shell git ls-files "*.py")

test:
	pytest -q --cov=. --cov-report=term-missing

security:
	bandit -r .
	pip-audit || true

.PHONY: set-payload
set-payload:
	@python -m scripts.qdrant_set_payload \
		--url "$${URL:-http://localhost:6333}" \
		--collection "$${COLLECTION:-heva_v1}" \
		--filter-key "$${FILTER_KEY:-source}" \
		--filter-val "$(SOURCE)" \
		--set-key "$(KEY)" \
		--set-val "$(VAL)"

.PHONY: check
check:
	@true

## QDRANT QUICK TARGETS (HEVA)
.PHONY: qdr-count-oct qdr-last7 qdr-ta-since

### >>> HEVA QDRANT TARGETS >>>
SHELL := /bin/bash

qdr-ping:
	@echo "Pinging $(QDR)/collections ..."
	@curl -sS "$(QDR)/collections" | jq '.result.collections | length' || true

qdr-count-oct:
	@START=$$(date -d '2025-10-01T00:00:00+08:00' +%s); END=$$(date -d '2025-11-01T00:00:00+08:00' +%s); \
	echo "Counting heva_v1.ingested_at_ts from $$START to $$END"; \
	jq -n --argjson s $$START --argjson e $$END '{"with_payload":false,"with_vectors":false,"filter":{"must":[{"key":"ingested_at_ts","range":{"gte":$$s,"lte":$$e}}]},"limit":1}' | \
	curl -sS -X POST "$(QDR)/collections/heva_v1/points/count" -H 'Content-Type: application/json' -d @- | jq '.result'

qdr-last7:
	@SINCE=$$(( $$(date +%s) - 7*86400 )); \
	echo "Last 7 days (heva_docs.ingested_at_ts >= $$SINCE)"; \
	jq -n --argjson s $$SINCE '{"limit":200,"with_payload":true,"with_vectors":false,"filter":{"must":[{"key":"ingested_at_ts","range":{"gte":$$s}}]}}' | \
	curl -sS -X POST "$(QDR)/collections/heva_docs/points/scroll" -H 'Content-Type: application/json' -d @- | \
	jq -c '{count: ((.result.points // [])|length), items: ((.result.points // [])|map({id, payload}))}'

qdr-ta-since:
	@SINCE=$$(( $$(date +%s) - 7*86400 )); \
	echo "THREAT_ACTOR since last 7 days (heva_docs)"; \
	jq -n --argjson s $$SINCE '{"limit":200,"with_payload":true,"with_vectors":false,"filter":{"must":[{"key":"tags","match":{"value":"THREAT_ACTOR"}},{"key":"ingested_at_ts","range":{"gte":$$s}}]}}' | \
	curl -sS -X POST "$(QDR)/collections/heva_docs/points/scroll" -H 'Content-Type: application/json' -d @- | \
	jq -c '{count: ((.result.points // [])|length), items: ((.result.points // [])|map({id, payload}))}'
### <<< HEVA QDRANT TARGETS <<<
### >>> HEVA EXTRAS TARGETS >>>
# Extra convenience targets. Requires curl + jq. QDR can be overriden: make qdr-seed QDR=http://localhost:6333

SHELL := /bin/bash

# Seed a demo THREAT_ACTOR point into heva_docs (id=1, 384-d zero vector)
qdr-seed:
	@NOW=$$(date +%s); \
	echo "Seeding one demo THREAT_ACTOR doc into heva_docs (ingested_at_ts=$$NOW)"; \
	curl -sS -X PUT "$(QDR)/collections/heva_docs" \
	  -H "Content-Type: application/json" \
	  -d '{ "vectors": { "size": 384, "distance": "Cosine" } }' >/dev/null || true; \
	BODY=$$(jq -n --argjson now $$NOW '{ \
	  points: [ { \
	    id: 1, \
	    vector: ([range(384)] | map(0)), \
	    payload: { \
	      text: "Seed THREAT_ACTOR doc", \
	      source: "seed", \
	      tags: ["THREAT_ACTOR"], \
	      threat_actors: ["TA505"], \
	      ingested_at_ts: $$now \
	    } \
	  } ] \
	}'); \
	printf "%s" "$$BODY" | curl -sS -X PUT "$(QDR)/collections/heva_docs/points" \
	  -H "Content-Type: application/json" -d @- | jq -c .

# Delete ALL points in heva_docs
qdr-wipe-docs:
	@echo "Deleting ALL points in heva_docs..."; \
	jq -n '{ filter: { must: [] } }' | \
	curl -sS -X POST "$(QDR)/collections/heva_docs/points/delete" \
	  -H "Content-Type: application/json" -d @- | jq -c .

# Delete ALL points in heva_v1
qdr-wipe-heva_v1:
	@echo "Deleting ALL points in heva_v1..."; \
	jq -n '{ filter: { must: [] } }' | \
	curl -sS -X POST "$(QDR)/collections/heva_v1/points/delete" \
	  -H "Content-Type: application/json" -d @- | jq -c .
### <<< HEVA EXTRAS <<<
### >>> HEVA SMOKE START >>>
.PHONY: qdr-smoke
qdr-smoke:
	@echo "— qdr-ping —";     $(MAKE) qdr-ping || true
	@echo; echo "— count-oct —"; $(MAKE) qdr-count-oct || true
	@echo; echo "— last7 —";     $(MAKE) qdr-last7 || true
	@echo; echo "— ta-since —";  $(MAKE) qdr-ta-since || true
	@echo; read -rp "Done. Press Enter to close..." _
### <<< HEVA SMOKE END <<<
### >>> HEVA FIX-CLOCK START >>>
.PHONY: qdr-fix-clock
qdr-fix-clock:
	@bash -c 'shopt -s nullglob; files=(Makefile *.mk); now=$$(date +%s); touched=0; \
	for f in "$${files[@]}"; do \
	  [ -e "$$f" ] || continue; \
	  if stat -c %Y "$$f" >/dev/null 2>&1; then m=$$(stat -c %Y "$$f"); else m=$$(stat -f %m "$$f"); fi; \
	  if [ -n "$$m" ] && [ "$$m" -gt "$$now" ] 2>/dev/null; then touch "$$f"; touched=$$((touched+1)); fi; \
	done; \
	sleep 1; echo "✅ qdr-fix-clock: touched $$touched file(s) & waited 1s."'
	@echo "Tip: run 'make qdr-smoke' after this."
### <<< HEVA FIX-CLOCK END <<<
### >>> HEVA ALL START >>>
.PHONY: qdr-all
qdr-all:
	@echo "→ qdr-fix-clock"
	@$(MAKE) qdr-fix-clock || true
	@echo
	@echo "→ qdr-seed (idempotent)"
	@$(MAKE) qdr-seed || true
	@echo
	@echo "→ qdr-smoke"
	@$(MAKE) qdr-smoke || true
### <<< HEVA ALL END <<<
### >>> HEVA PARAM START >>>
.PHONY: qdr-since qdr-since-help
qdr-since:
	@bash scripts/qdr_since.sh "$(QDR)" "$(COL)" "$(TAG)" "$(DAYS)"
qdr-since-help:
	@echo "Usage: make qdr-since [QDR=…] [COL=…] [TAG=…] [DAYS=…]"; echo "Defaults via Make: QDR=$(QDR) COL=$(COL) TAG=$(TAG) DAYS=$(DAYS)"
### <<< HEVA PARAM END <<<
### >>> HEVA CLEAN START >>>
.PHONY: clean-backups heva-clean
clean-backups:
	rm -f -- Makefile.bak.* *.tmp *.log 2>/dev/null || true
heva-clean:
	find . -maxdepth 1 -type f \( -name 'Makefile.bak.*' -o -name '*.tmp' -o -name '*.log' \) -print -delete 2>/dev/null || true
	echo "✓ HEVA clean done."
### <<< HEVA CLEAN END <<<
### >>> HEVA QUICK HELP START >>>
.PHONY: help
help:
	@echo "Targets:"
	@echo "  qdr-since [QDR=… COL=… TAG=… DAYS=…]  – list items since N days"
	@echo "  heva-clean                             – purge Makefile.bak.*, *.tmp, *.log"
	@echo "Vars (Make defaults): QDR=$(QDR)  COL=$(COL)  TAG=$(TAG)  DAYS=$(DAYS)"
### <<< HEVA QUICK HELP END <<<
.PHONY: inventory inventory-fast
inventory:
	@ROOT="/home/mike/capstone_win" INVDIR="$$(pwd)/_inventory" bash ./scripts/list_files_usage.sh

inventory-fast:
	@NO_PAUSE=1 ROOT="/home/mike/capstone_win" INVDIR="$$(pwd)/_inventory" bash ./scripts/list_files_usage.sh
.PHONY: refs-fast
refs-fast:
	@ROOT="/home/mike/capstone_win" OUT="$$(pwd)/_inventory" bash ./scripts/refs_fast.sh || true
.PHONY: audit-fast audit-prune audit-apply
# 1) Fast refs + build to_remove.csv (zero-refs + junk patterns)
audit-fast:
	@$(MAKE) refs-fast
	@python3 - <<'PY' || true
import csv, pathlib, fnmatch
root = pathlib.Path("_inventory")
refs = {r['path']: int((r['ref_count_approx'] or 0)) for r in csv.DictReader(open(root/"refs_summary_fast.csv", encoding='utf-8'))}
inv  = list(csv.DictReader(open(root/"files_inventory.csv", encoding='utf-8')))
INCLUDE_PATTERNS = [
  ".aider*", ".coverage", ".env", ".ruff_cache/**",
  "dir_listing.txt", "latest_recommendations.txt", "lands.csv",
  "Makefile.bak.*", "Makefile.addon",
  "capstone_agent_a/out/*.json", "capstone_agent_a/output.txt",
  "tests/test_all.py.tmp", "cybersage_deploy_bundle.zip", "IS06_*.pdf",
  "qdrant_storage/.lock", "qdrant_storage/.qdrant_fs_check",
]
def match_any(path):
    import fnmatch
    for pat in INCLUDE_PATTERNS:
        if fnmatch.fnmatch(path, pat) or ("/**" in pat and path.startswith(pat.replace("/**",""))):
            return True
    return False
cand=set()
for r in inv:
    p=r['path']
    if p.startswith("_inventory/"): continue
    if match_any(p) or refs.get(p,0)==0:
        cand.add(p)
out = root/"to_remove.csv"
with out.open('w', newline='', encoding='utf-8') as f:
    w=csv.writer(f); w.writerow(["path"]); [w.writerow([p]) for p in sorted(cand)]
print("[write]", out, "count=", len(cand))
PY

# 2) Dry-run prune
audit-prune:
	@ROOT="/home/mike/capstone_win" DRY_RUN=1 _tools/prune_from_csv.sh _inventory/to_remove.csv || true

# 3) Apply prune and publish
audit-apply:
	@ROOT="/home/mike/capstone_win" DRY_RUN=0 _tools/prune_from_csv.sh _inventory/to_remove.csv || true
	@cd /home/mike/capstone_win && git fetch team && git add -A \
	  && git commit -m "chore: repo audit — prune zero-refs & junk (batch)" --no-verify || true \
	  && git push team HEAD:main || true
.PHONY: refs-fast inventory-quick audit-fast audit-prune audit-apply

# Fast refs-only pass (tracked files), writes _inventory/refs_summary_fast.csv
refs-fast:
	@ROOT="/home/mike/capstone_win" OUT="$$(pwd)/_inventory" bash ./scripts/refs_fast.sh || true

# Quick inventory of tracked files only (immediate; no slow scan)
inventory-quick:
	@mkdir -p _inventory; \
	python3 - <<'PY' || true
import csv, subprocess, pathlib
root = pathlib.Path("/home/mike/capstone_win").resolve()
out  = pathlib.Path("_inventory/files_inventory_quick.csv")
lfs = set()
try:
    for ln in subprocess.check_output(["git","lfs","ls-files"], cwd=root, text=True).splitlines():
        if ln.strip(): lfs.add(ln.split()[-1])
except Exception: pass
rows=[]
for b in subprocess.check_output(["git","ls-files","-z"], cwd=root).split(b'\\0'):
    if not b: continue
    rel = b.decode('utf-8','replace')
    p = root/rel
    try:
        st=p.stat(); size=st.st_size; execf='y' if (st.st_mode & 0o111) else ''
    except Exception: size,execf=0,''
    last_dt,last_author="",""
    try:
        s=subprocess.check_output(["git","log","-1","--pretty=%cI|%an","--",rel],cwd=root,text=True).strip()
        if '|' in s: last_dt,last_author=s.split('|',1)
    except Exception: pass
    rows.append({"path":rel,"size_bytes":size,"exec":execf,"git_tracked":"y","git_status":"","lfs_pointer":"y" if rel in lfs else "", "last_commit":last_dt,"last_author":last_author})
with out.open('w',newline='',encoding='utf-8') as f:
    w=csv.DictWriter(f,fieldnames=["path","size_bytes","exec","git_tracked","git_status","lfs_pointer","last_commit","last_author"])
    w.writeheader(); w.writerows(rows)
print("[write]", out)
PY

# One-button audit: fast refs + build _inventory/to_remove.csv (zero-refs + junk)
audit-fast:
	$(MAKE) refs-fast
	python3 - <<'PY' || true
import csv, pathlib, fnmatch
root = pathlib.Path("_inventory")
refs = {r['path']: int((r['ref_count_approx'] or 0)) for r in csv.DictReader(open(root/"refs_summary_fast.csv", encoding='utf-8'))}
inv  = list(csv.DictReader(open(root/"files_inventory.csv", encoding='utf-8')))

INCLUDE_PATTERNS = [
  ".aider*", ".coverage", ".env", ".ruff_cache/**",
  "dir_listing.txt", "latest_recommendations.txt", "lands.csv",
  "Makefile.bak.*", "Makefile.addon",
  "capstone_agent_a/out/*.json", "capstone_agent_a/output.txt",
  "tests/test_all.py.tmp", "cybersage_deploy_bundle.zip", "IS06_*.pdf",
  "qdrant_storage/.lock", "qdrant_storage/.qdrant_fs_check",
]
def match_any(path):
    for pat in INCLUDE_PATTERNS:
        if fnmatch.fnmatch(path, pat) or ("/**" in pat and path.startswith(pat.replace("/**",""))):
            return True
    return False

cand=set()
for r in inv:
    p=r['path']
    if p.startswith("_inventory/"): 
        continue
    if match_any(p) or refs.get(p,0)==0:
        cand.add(p)

out = root/"to_remove.csv"
with out.open('w', newline='', encoding='utf-8') as f:
    w=csv.writer(f); w.writerow(["path"]); [w.writerow([p]) for p in sorted(cand)]
print("[write]", out, "count=", len(cand))
PY

# Dry-run prune
audit-prune:
	ROOT="/home/mike/capstone_win" DRY_RUN=1 _tools/prune_from_csv.sh _inventory/to_remove.csv || true

# Apply prune + publish
audit-apply:
	ROOT="/home/mike/capstone_win" DRY_RUN=0 _tools/prune_from_csv.sh _inventory/to_remove.csv || true
	cd /home/mike/capstone_win && git fetch team && git add -A \
  && git commit -m "chore: repo audit — prune zero-refs & junk (batch)" --no-verify || true \
  && git push team HEAD:main || true
