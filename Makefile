SHELL := /usr/bin/env bash

.DEFAULT_GOAL := help

# Toolchain defaults
PODMAN_MACHINE ?= podman-machine-default
ACT_CONTAINER_ARCH ?= linux/amd64
ACT_CONTAINER_DAEMON_SOCKET ?= -
ACT_ARGS ?=
ACT_DEFAULT_ARGS ?= --pull=false --reuse

UV ?= uv
UV_RUN := $(UV) run

# ANSI colors
RESET := \033[0m
BOLD := \033[1m
BLUE := \033[34m
CYAN := \033[36m
GREEN := \033[32m
YELLOW := \033[33m

define info
@printf "$(BOLD)$(BLUE)==>$(RESET) %s\n" "$(1)"
endef

define ok
@printf "$(GREEN)%s$(RESET)\n" "$(1)"
endef

define require_uv
@if ! command -v $(UV) >/dev/null 2>&1; then \
  printf "$(YELLOW)uv not found. Install from https://docs.astral.sh/uv/getting-started/installation/$(RESET)\n" >&2; \
  exit 1; \
fi
endef

.PHONY: help \
	format format-fix lint lint-fix typecheck test test-validate check ci \
	build build-check clean clean-dist \
	act act-validate act-dryrun-pytest act-pytest

##@ Quality
format: ## Check formatting with Ruff
	$(call require_uv)
	$(call info,Checking formatting)
	$(UV_RUN) --extra lint ruff format . --check
	$(call ok,Formatting check passed)

format-fix: ## Auto-format code with Ruff
	$(call require_uv)
	$(call info,Formatting source files)
	$(UV_RUN) --extra lint ruff format .
	$(call ok,Formatting completed)

lint: ## Run Ruff lint checks
	$(call require_uv)
	$(call info,Running lint checks)
	$(UV_RUN) --extra lint ruff check .
	$(call ok,Lint checks passed)

lint-fix: ## Run Ruff lint checks with autofix
	$(call require_uv)
	$(call info,Running lint autofix)
	$(UV_RUN) --extra lint ruff check . --fix
	$(call ok,Lint autofix completed)

typecheck: ## Run mypy type checks
	$(call require_uv)
	$(call info,Running type checks)
	$(UV_RUN) --extra lint mypy .
	$(call ok,Type checks passed)

test: ## Run full test suite
	$(call require_uv)
	$(call info,Running test suite)
	$(UV_RUN) --extra test pytest -q
	$(call ok,Tests passed)

test-validate: ## Run only validate session tests
	$(call require_uv)
	$(call info,Running tests/test_validate.py)
	$(UV_RUN) --extra test pytest -q tests/test_validate.py
	$(call ok,Validate tests passed)

check: format lint typecheck test ## Run full local quality gate

ci: check build-check ## Run local CI gate (quality + packaging)

##@ Build
build: clean-dist ## Build source and wheel distributions
	$(call require_uv)
	$(call info,Building distributions)
	$(UV_RUN) --with build python -m build
	$(call ok,Build completed)

build-check: build ## Validate built artifacts with twine
	$(call require_uv)
	$(call info,Checking built artifacts)
	$(UV_RUN) --with twine twine check dist/*
	$(call ok,Artifact checks passed)

clean: ## Remove local caches and test/build artifacts
	$(call info,Cleaning repository artifacts)
	rm -rf .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage
	find . -name "__pycache__" -type d -prune -exec rm -rf {} +
	find . -name "*.pyc" -type f -delete
	$(call ok,Cleanup completed)

clean-dist: ## Remove dist and build directories
	$(call info,Cleaning distribution directories)
	rm -rf dist build *.egg-info
	$(call ok,Distribution directories cleaned)

##@ Local Actions (Podman + act)
act: ## Run act with Podman socket and sane defaults (use ACT_ARGS='...')
	@set -euo pipefail; \
	printf "$(BOLD)$(BLUE)==>$(RESET) %s\n" "Resolving Podman socket"; \
	socket="$${PODMAN_SOCKET:-}"; \
	if [[ -z "$$socket" ]]; then \
	  socket="$$(podman machine inspect "$(PODMAN_MACHINE)" --format '{{.ConnectionInfo.PodmanSocket.Path}}' 2>/dev/null | head -n1 || true)"; \
	fi; \
	if [[ -z "$$socket" ]]; then \
	  printf "$(YELLOW)Podman socket not found. Start Podman with: podman machine start $(PODMAN_MACHINE)$(RESET)\n" >&2; \
	  exit 1; \
	fi; \
	[[ "$$socket" == unix://* ]] || socket="unix://$$socket"; \
	printf "$(BOLD)$(CYAN)DOCKER_HOST=$(RESET)%s\n" "$$socket"; \
	DOCKER_HOST="$$socket" act \
	  $(ACT_DEFAULT_ARGS) \
	  --container-daemon-socket "$(ACT_CONTAINER_DAEMON_SOCKET)" \
	  --container-architecture "$(ACT_CONTAINER_ARCH)" \
	  $(ACT_ARGS)

act-validate: ACT_ARGS=--validate
act-validate: act ## Validate workflow files with act + Podman

act-dryrun-pytest: ACT_ARGS=-n pull_request -j pytest
act-dryrun-pytest: act ## Dry-run unittest job with act + Podman

act-pytest: ACT_ARGS=pull_request -j pytest
act-pytest: act ## Execute unittest job with act + Podman

##@ Help
help: ## Show this help with grouped targets
	@awk 'BEGIN {FS = ":.*##"; printf "\n$(BOLD)$(CYAN)pyicloud development targets$(RESET)\n"} \
	/^##@/ {printf "\n$(BOLD)%s$(RESET)\n", substr($$0, 5); next} \
	/^[a-zA-Z0-9_.-]+:.*##/ {printf "  $(GREEN)%-22s$(RESET) %s\n", $$1, $$2}' $(MAKEFILE_LIST)
