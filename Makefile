.DEFAULT_GOAL := help
PY := .venv/bin/python
SHELL := /bin/bash
UV := uv

# Everything runs against the uv-managed venv, never against a system interpreter,
# so local and CI behaviour match.
export RUFF_CACHE_DIR := .cache/ruff
export MYPY_CACHE_DIR := .cache/mypy
export PRE_COMMIT_HOME := .cache/pre-commit
export PYTHONDONTWRITEBYTECODE := 1

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: install
install: ## Create the venv and install all dependency groups
	$(UV) sync --all-extras --group dev
	$(UV) run pre-commit install --install-hooks

.PHONY: sync
sync: ## Re-sync the environment with the lockfile
	$(UV) lock --check 2>/dev/null || $(UV) lock
	$(UV) sync --locked --all-extras --group dev

.PHONY: test
test: ## Run the test suite
	$(UV) run pytest -q

.PHONY: cov
cov: ## Run tests with coverage
	$(UV) run pytest -q --cov --cov-report=term-missing

.PHONY: lint
lint: ## ruff check + format check
	$(UV) run ruff check .
	$(UV) run ruff format --check .

.PHONY: fix
fix: ## Auto-fix lint/format issues
	$(UV) run ruff check --fix .
	$(UV) run ruff format .

.PHONY: type
type: ## mypy --strict
	$(UV) run mypy

.PHONY: check
check: lint type test ## What CI runs (quality + tests)

.PHONY: precommit
precommit: ## Run the full pre-commit suite over every file
	$(UV) run pre-commit run --all-files --show-diff-on-failure

.PHONY: clean
clean: ## Remove caches and build artefacts
	rm -rf .cache .pytest_cache .ruff_cache .mypy_cache build dist htmlcov .coverage
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
