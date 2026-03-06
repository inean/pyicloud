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
PODMAN ?= podman
PODMAN_COMPOSE := $(PODMAN) compose
OBSERVABILITY_COMPOSE_FILE ?= ops/observability/docker-compose.yml
API_HOST ?= 127.0.0.1
API_PORT ?= 8000
API_URL ?= http://$(API_HOST):$(API_PORT)
API_LOG_FILE ?= /tmp/pyicloud-api.log
UPSTREAM_ALLOWED_ENVS ?= dev,qa
UPSTREAM_CAPTURE_BODY_MAX_BYTES ?= 16384
OBSERVABILITY_TIMEOUT_SECONDS ?= 10
PROMQL_ENDPOINT ?= http://127.0.0.1:9090/api/v1/query
TRACEQL_ENDPOINT ?= http://127.0.0.1:3200/api/search
LOGQL_ENDPOINT ?= http://127.0.0.1:3100/loki/api/v1/query
FLOW_FORMAT ?= table
QUALITY_HOTSPOT_PATHS ?= pyicloud/api/errors.py pyicloud/application/api_auth.py pyicloud/application/core_services.py pyicloud/adapters/services/runtime.py tests/integration/test_challenge_contract_gate.py tests/unit/test_hexagonal_import_boundaries.py tests/unit/test_legacy_alias_export_ratchet.py
MYPY_HOTSPOT_MODULES ?= pyicloud/application/api_auth.py pyicloud/application/core_services.py pyicloud/api/errors.py pyicloud/adapters/services/runtime.py
HOTSPOT_TEST_TARGETS ?= tests/integration/test_challenge_contract_gate.py tests/vertical/api/test_upstream_error_mapping.py tests/unit/test_api_auth_service.py tests/unit/test_core_services_async_contract.py tests/unit/test_legacy_core_services_adapter.py

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
define require_jq
@if ! command -v jq >/dev/null 2>&1; then \
  printf "$(YELLOW)jq not found. Install jq to use this target.$(RESET)\n" >&2; \
  exit 1; \
fi
endef

.PHONY: help \
		format format-fix lint lint-fix typecheck test test-hotspots test-ratchet test-validate check ci \
		build build-check clean clean-dist \
		act act-validate act-dryrun-pytest act-pytest \
		observability-up observability-down observability-ps observability-logs api-observability-upstream \
		auth-login auth-security-code devices-list flow-timeline auth-flow

##@ Quality
format: ## Check formatting with Ruff
	$(call require_uv)
	$(call info,Checking formatting)
	$(UV_RUN) --extra lint ruff format $(QUALITY_HOTSPOT_PATHS) --check
	$(call ok,Formatting check passed)

format-fix: ## Auto-format code with Ruff
	$(call require_uv)
	$(call info,Formatting source files)
	$(UV_RUN) --extra lint ruff format $(QUALITY_HOTSPOT_PATHS)
	$(call ok,Formatting completed)

lint: ## Run Ruff lint checks
	$(call require_uv)
	$(call info,Running lint checks)
	$(UV_RUN) --extra lint ruff check $(QUALITY_HOTSPOT_PATHS)
	$(call ok,Lint checks passed)

lint-fix: ## Run Ruff lint checks with autofix
	$(call require_uv)
	$(call info,Running lint autofix)
	$(UV_RUN) --extra lint ruff check $(QUALITY_HOTSPOT_PATHS) --fix
	$(call ok,Lint autofix completed)

typecheck: ## Run mypy type checks
	$(call require_uv)
	$(call info,Running type checks)
	$(UV_RUN) --extra lint mypy --follow-imports=skip $(MYPY_HOTSPOT_MODULES)
	$(call ok,Type checks passed)

test: ## Run full test suite
	$(call require_uv)
	$(call info,Running test suite)
	$(UV_RUN) --extra test pytest -q
	$(call ok,Tests passed)

test-hotspots: ## Run challenge/runtime hotspot coverage gate
	$(call require_uv)
	$(call info,Running hotspot coverage gate)
	$(UV_RUN) --extra test pytest -q -o addopts='' \
		--cov=pyicloud.application.api_auth \
		--cov=pyicloud.api.errors \
		--cov=pyicloud.adapters.services.runtime \
		--cov=pyicloud.adapters.services \
		--cov-report=term-missing \
		--cov-fail-under=82 \
		$(HOTSPOT_TEST_TARGETS)
	$(call ok,Hotspot coverage gate passed)

test-ratchet: ## Run tests with baseline-failure ratchet policy
	$(call require_uv)
	$(call info,Running test suite with ratchet baseline)
	$(UV_RUN) --extra test python scripts/pytest_ratchet.py
	$(call ok,Ratchet gate passed)

test-validate: ## Run only validate session tests
	$(call require_uv)
	$(call info,Running tests/test_validate.py)
	$(UV_RUN) --extra test pytest -q tests/test_validate.py
	$(call ok,Validate tests passed)

check: format lint typecheck test-hotspots test ## Run full local quality gate

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

##@ Observability
observability-up: ## Start local Grafana/Prometheus/Tempo/Loki stack with Podman Compose
	$(call info,Starting observability stack)
	$(PODMAN_COMPOSE) -f $(OBSERVABILITY_COMPOSE_FILE) up -d
	$(call ok,Observability stack started)

observability-down: ## Stop and remove local observability stack
	$(call info,Stopping observability stack)
	$(PODMAN_COMPOSE) -f $(OBSERVABILITY_COMPOSE_FILE) down
	$(call ok,Observability stack stopped)

observability-ps: ## Show observability stack containers
	$(call info,Listing observability services)
	$(PODMAN_COMPOSE) -f $(OBSERVABILITY_COMPOSE_FILE) ps

observability-logs: ## Tail observability stack logs (set OBS_SERVICE=<service> to filter)
	@if [[ -n "$${OBS_SERVICE:-}" ]]; then \
	  $(PODMAN_COMPOSE) -f $(OBSERVABILITY_COMPOSE_FILE) logs -f "$$OBS_SERVICE"; \
	else \
	  $(PODMAN_COMPOSE) -f $(OBSERVABILITY_COMPOSE_FILE) logs -f; \
	fi

api-observability-upstream: ## Run API in dev with upstream MITM capture + observability endpoints configured
	$(call require_uv)
	$(call info,Starting pyicloud API with upstream capture enabled)
	PYICLOUD_API_ENV=dev \
	PYICLOUD_API_HOST=$(API_HOST) \
	PYICLOUD_API_PORT=$(API_PORT) \
	PYICLOUD_UPSTREAM_CAPTURE_ENABLED=true \
	PYICLOUD_UPSTREAM_PROBE_ADAPTER=otel \
	PYICLOUD_UPSTREAM_ALLOWED_ENVS=$(UPSTREAM_ALLOWED_ENVS) \
	PYICLOUD_UPSTREAM_CAPTURE_BODY_MAX_BYTES=$(UPSTREAM_CAPTURE_BODY_MAX_BYTES) \
	PYICLOUD_OBSERVABILITY_ADAPTER=otel \
	PYICLOUD_OBSERVABILITY_PROMQL_ENDPOINT=$(PROMQL_ENDPOINT) \
	PYICLOUD_OBSERVABILITY_TRACEQL_ENDPOINT=$(TRACEQL_ENDPOINT) \
	PYICLOUD_OBSERVABILITY_LOGQL_ENDPOINT=$(LOGQL_ENDPOINT) \
	PYICLOUD_OBSERVABILITY_TIMEOUT_SECONDS=$(OBSERVABILITY_TIMEOUT_SECONDS) \
	$(UV_RUN) icloud-api | tee $(API_LOG_FILE)

auth-login: ## Run CLI auth login (requires APPLE_ID and APPLE_PASSWORD env vars)
	$(call require_uv)
	@if [[ -z "$${APPLE_ID:-}" || -z "$${APPLE_PASSWORD:-}" ]]; then \
	  printf "$(YELLOW)Set APPLE_ID and APPLE_PASSWORD before running this target.$(RESET)\n" >&2; \
	  exit 1; \
	fi
	PYICLOUD_API_URL=$(API_URL) \
	$(UV_RUN) icloud auth login --username "$$APPLE_ID" --password "$$APPLE_PASSWORD"

auth-security-code: ## Complete auth challenge (requires CHALLENGE_ID and SECURITY_CODE env vars)
	$(call require_uv)
	@if [[ -z "$${CHALLENGE_ID:-}" || -z "$${SECURITY_CODE:-}" ]]; then \
	  printf "$(YELLOW)Set CHALLENGE_ID and SECURITY_CODE before running this target.$(RESET)\n" >&2; \
	  exit 1; \
	fi
	PYICLOUD_API_URL=$(API_URL) \
	$(UV_RUN) icloud auth security-code --challenge-id "$$CHALLENGE_ID" --code "$$SECURITY_CODE"

devices-list: ## Run devices list against API using stored local token
	$(call require_uv)
	PYICLOUD_API_URL=$(API_URL) \
	$(UV_RUN) icloud devices list

flow-timeline: ## Render flow timeline (requires FLOW_ID; optional FLOW_FORMAT=table|json)
	$(call require_uv)
	@if [[ -z "$${FLOW_ID:-}" ]]; then \
	  printf "$(YELLOW)Set FLOW_ID before running this target.$(RESET)\n" >&2; \
	  exit 1; \
	fi
	PYICLOUD_API_URL=$(API_URL) \
	$(UV_RUN) icloud observability flow --flow-id "$$FLOW_ID" --format "$(FLOW_FORMAT)"

auth-flow: ## Execute login + optional 2FA + devices list and print FLOW_ID (requires APPLE_ID and APPLE_PASSWORD)
	$(call require_uv)
	$(call require_jq)
	@if [[ -z "$${APPLE_ID:-}" || -z "$${APPLE_PASSWORD:-}" ]]; then \
	  printf "$(YELLOW)Set APPLE_ID and APPLE_PASSWORD before running this target.$(RESET)\n" >&2; \
	  exit 1; \
	fi

	@set -euo pipefail; \
	login_json="$$(PYICLOUD_API_URL=$(API_URL) $(UV_RUN) icloud auth login --username "$$APPLE_ID" --password "$$APPLE_PASSWORD")"; \
	printf "%s\n" "$$login_json"; \
	status="$$(printf "%s" "$$login_json" | jq -r '.status')"; \
	flow_id="$$(printf "%s" "$$login_json" | jq -r '.flow_id // empty')"; \
	if [[ "$$status" == "challenge_required" ]]; then \
	  challenge_id="$$(printf "%s" "$$login_json" | jq -r '.challenge_id')"; \
	  if [[ -z "$${SECURITY_CODE:-}" ]]; then \
	    read -r -p "SECURITY_CODE: " security_code; \
	  else \
	    security_code="$$SECURITY_CODE"; \
	  fi; \
	  login2_json="$$(PYICLOUD_API_URL=$(API_URL) $(UV_RUN) icloud auth security-code --challenge-id "$$challenge_id" --code "$$security_code")"; \
	  printf "%s\n" "$$login2_json"; \
	  flow_id="$$(printf "%s" "$$login2_json" | jq -r '.flow_id // empty')"; \
	fi; \
	PYICLOUD_API_URL=$(API_URL) $(UV_RUN) icloud devices list; \
	printf "FLOW_ID=%s\n" "$$flow_id"

##@ Help
help: ## Show this help with grouped targets
	@awk 'BEGIN {FS = ":.*##"; printf "\n$(BOLD)$(CYAN)pyicloud development targets$(RESET)\n"} \
	/^##@/ {printf "\n$(BOLD)%s$(RESET)\n", substr($$0, 5); next} \
	/^[a-zA-Z0-9_.-]+:.*##/ {printf "  $(GREEN)%-22s$(RESET) %s\n", $$1, $$2}' $(MAKEFILE_LIST)
