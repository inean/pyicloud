# Contributing to pyicloud

Thanks for contributing.

## Current architecture

This repository targets an API-first and CLI-first runtime.

Public usage surfaces:
- FastAPI routes under `pyicloud/api/app.py` (`/v1/*`)
- CLI subcommands under `pyicloud/cli/main.py` (`icloud ...`)

Retired public surfaces (do not reintroduce):
- `from pyicloud import PyiCloudService`
- `pyicloud.services`
- `pyicloud.legacy`
- `pyicloud.cmdline`

## Development setup

### Prerequisites

- `uv`
- `git`
- Optional for local GitHub Actions runs: `act` + `podman`

### Clone and install

```bash
git clone <repo-url>
cd pyicloud
uv sync --extra dev
make help
```

## Local quality checks

```bash
make format
make lint
make typecheck
make test
make test-ratchet
make build-check

# Autofix helpers
make format-fix
make lint-fix

# Full local gate
make ci
```

## Repository structure

Top-level:
- `pyicloud/`: source code
- `tests/`: unit/integration/smoke/vertical tests
- `.github/workflows/`: CI workflows
- `Makefile`: local lifecycle entrypoint
- `pyproject.toml`: dependencies and tool config

Important package areas:
- `pyicloud/api/` + `pyicloud/cli/`
  - Primary product surface.
- `pyicloud/application/`
  - Use-case façades (`api_auth`, `core_services`, `observability`).
- `pyicloud/adapters/`
  - Infrastructure adapters (auth/session/store/services/observability).
- `pyicloud/ports/`
  - Hexagonal ports/contracts for app-adapter boundaries.
- `pyicloud/sessions/` + `pyicloud/trees/`
  - Typed auth/session transport and flow orchestration.
- `pyicloud/models/`
  - Shared typed models and settings.

## Test layout

- `tests/unit`: focused module/adapter tests
- `tests/integration`: multi-layer in-process tests
- `tests/smoke`: lightweight runtime checks
- `tests/vertical`: API+CLI end-to-end over ASGI transport

Network guardrail:
- External network is blocked by default in the test suite.
- If a test genuinely needs network, add `@pytest.mark.allow_network` and justify it in test comments.

## Pull request expectations

- Keep changes focused.
- Add/update tests for behavior changes.
- Run the local quality checks before opening a PR.
- Update docs for user-facing or contributor workflow changes.
- Do not reintroduce retired legacy import surfaces.
