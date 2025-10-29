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
