SHELL := /bin/bash

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
QDR ?= http://127.0.0.1:6333

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
QDR ?= http://127.0.0.1:6333

qdr-seed:
	@NOW=$$(date +%s); \
	echo "Seeding one demo THREAT_ACTOR doc into heva_docs (ingested_at_ts=$$NOW)"; \
	# ensure collection exists (idempotent); vectors size is arbitrary since we only scroll/count here
	curl -sS -X PUT "$(QDR)/collections/heva_docs" \
	  -H 'Content-Type: application/json' \
	  -d '{ "vectors": { "size": 4, "distance": "Cosine" } }' >/dev/null || true; \
	jq -n --argjson now $$NOW '{
	  points: [{
	    id: $now,
	    vector: [0,0,0,0],
	    payload: {
	      text: "Seed THREAT_ACTOR doc",
	      source: "seed",
	      tags: ["THREAT_ACTOR"],
	      threat_actors: ["TA505"],
	      ingested_at_ts: $now
	    }
	  }]
	}' | curl -sS -X PUT "$(QDR)/collections/heva_docs/points" \
	  -H 'Content-Type: application/json' -d @- | jq -r '.status' || true

qdr-wipe-docs:
	@echo "Deleting collection heva_docs (DANGER)"; \
	curl -sS -X DELETE "$(QDR)/collections/heva_docs" | jq -r '.status' || true

qdr-wipe-heva_v1:
	@echo "Deleting collection heva_v1 (DANGER)"; \
	curl -sS -X DELETE "$(QDR)/collections/heva_v1" | jq -r '.status' || true
### <<< HEVA EXTRAS TARGETS <<<
### >>> HEVA EXTRAS >>>
SHELL := /bin/bash
QDR ?= http://127.0.0.1:6333

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
