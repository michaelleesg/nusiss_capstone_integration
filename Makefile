.PHONY: lint format test security check all up down ingest search eval

lint:
	ruff check --fix $(shell git ls-files "*.py")

format:
	black $(shell git ls-files "*.py")

test:
	pytest -q --cov=. --cov-report=term-missing

security:
	bandit -r .
	pip-audit || true

check: lint format test security

all: check export-eval

.PHONY: export-eval
# Copy evaluation artefacts into the external eval repo (symlinked).
# Usage: make export-eval FROM=observability/to_copy.txt
# By default, exports common artefacts if FROM not provided.
export-eval:
	@mkdir -p eval_external/eval_results
	@if [ -n "$$FROM" ]; then \
	  echo "Exporting $$FROM -> eval_external/eval_results/"; \
	  cp -r $$FROM eval_external/eval_results/ ; \
	else \
	  echo "Exporting default artefacts to eval_external/eval_results/"; \
	  cp -r observability/*.json eval_external/eval_results/ 2>/dev/null || true; \
	  cp -r docs/model_card_heva.md docs/governance_imda.md eval_external/eval_results/ 2>/dev/null || true; \
	  cp -r eval/datasets/*.jsonl eval_external/eval_results/ 2>/dev/null || true; \
	fi
