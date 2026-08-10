# CyberOps Kit — development commands.
.DEFAULT_GOAL := help
.PHONY: help install lint format typecheck test test-integration invariants coverage docs selfscan clean build

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Editable install + dev extras + pre-commit hooks
	python -m pip install -e ".[dev,docs]"
	pre-commit install || echo "pre-commit not available; skipping hook install"

lint: ## ruff check + ruff format --check
	python -m ruff check src/ tests/
	python -m ruff format --check src/ tests/

format: ## Apply ruff formatting and safe fixes
	python -m ruff check --fix src/ tests/
	python -m ruff format src/ tests/

typecheck: ## mypy --strict on src/
	python -m mypy

test: ## pytest, unit + invariants
	python -m pytest tests/unit tests/invariants

test-integration: ## Requires Docker and the external scanner binaries
	python -m pytest tests/integration -m integration

invariants: ## Run only tests/invariants — do this before every commit
	python -m pytest tests/invariants -v

coverage: ## Enforce the 80% floor on core/
	python -m pytest tests/ --cov=src/cyberops_kit/core --cov-report=term-missing --cov-fail-under=80

docs: ## Serve the documentation site
	python -m mkdocs serve

selfscan: ## Run CyberOps Kit against this repository
	python -m cyberops_kit.cli scan . --output .cyberops

build: ## Build the distribution
	python -m pip install --quiet build && python -m build

clean: ## Remove build and cache artifacts
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
