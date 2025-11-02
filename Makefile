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
