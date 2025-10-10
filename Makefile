.PHONY: lint format test security check all

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

all: check

