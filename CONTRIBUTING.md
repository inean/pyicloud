# Contributing to pyicloud

Thanks for contributing.

## Legacy status

This repo is a legacy fork that has not fully migrated to the newer logic yet.
When changing behavior, prefer incremental updates that keep compatibility with
existing tests and public interfaces unless a migration task explicitly says
otherwise.

## Migration scope (current)

- Migrated/modernized areas:
  - Typed request/response transport modules under `pyicloud/sessions/`
  - Behavior-tree orchestration under `pyicloud/trees/`
  - Structured models and validation under `pyicloud/models/`
- Legacy/partially migrated areas:
  - Main synchronous API and auth flow in `pyicloud/base.py`
  - CLI behavior in `pyicloud/cmdline.py`
  - Service layer behavior where legacy and newer patterns currently coexist
- Contributor guidance:
  - Prefer incremental refactors over large rewrites
  - Preserve public behavior unless the change is an explicit migration step
  - Keep tests updated when touching migration boundaries
  - Treat `kkza.py` as a behavioral reference for intended login/session flow, even though its implementation is intentionally rough

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

Run the same categories used in CI:

```bash
make format
make lint
make typecheck
make test
make build-check

# autofix helpers
make format-fix
make lint-fix

# or run the full local gate
make ci
```

## Run GitHub Actions locally (act + Podman)

Run local workflow checks through the Makefile:

```bash
make act-validate
make act-dryrun-pytest
make act-pytest
```

Notes:

- Start Podman first: `podman machine start`
- `make act*` resolves the Podman socket and sets `DOCKER_HOST` automatically.
- `make act*` also applies `act` defaults internally (`--pull=false --reuse`), so no `.actrc` is required.
- Default architecture is `linux/amd64`; override with `ACT_CONTAINER_ARCH`.
- Container daemon socket bind-mount is disabled by default (`ACT_CONTAINER_DAEMON_SOCKET=-`) to avoid macOS Podman mount issues.
- For custom `act` arguments, use `make act ACT_ARGS='...'`.
- All lifecycle targets use `uv` under the hood.

## Repository structure

Top-level directories and files:

- `pyicloud/`: library source code
- `tests/`: unit tests and fixtures
- `.github/workflows/`: CI workflows
- `Makefile`: local development lifecycle entrypoint
- `pyproject.toml`: packaging metadata, dependencies, and tool configuration

Important package areas:

- `pyicloud/base.py`
  - Primary public entrypoint (`PyiCloud`) and legacy synchronous authentication/session orchestration.
  - Loads persisted settings/cookies and drives sign-in, 2FA, trust, and session validation.
- `pyicloud/sessions/`
  - Typed request/response transports for auth/session endpoints (`signin`, `validate`, `trust`, `security_code`, `account_login`).
  - Uses Pydantic models for headers, cookies, and bodies.
- `pyicloud/trees/`
  - Behavior-tree orchestration for setup and renewal flows (`SetupModelTree`, `SessionModelTree`, `RenewModelTree`).
  - Encapsulates state transitions for login, 2FA verification, trust, and refresh.
- `pyicloud/services/`
  - Service clients for iCloud domains (`account`, `drive`, `photos`, `calendar`, `contacts`, `findmyiphone`, `reminders`, `ubiquity`).
  - Built from discovered webservice endpoints after authentication.
- `pyicloud/models/`
  - Core data models, typed fields, headers/cookies schemas, and settings models.
- `pyicloud/paths.py`
  - Persistence helpers for settings/cookies files.
- `pyicloud/log/`
  - Logging setup and HTTP transport logging hooks.

## How the code works

Authentication and session lifecycle, at a high level:

1. `PyiCloud(username, password)` builds a `Settings` model and loads persisted state from disk.
2. `authenticate()` tries token/cookie validation first.
3. If session is not valid, sign-in is performed, then 2FA/2SA challenges are resolved when required.
4. Trust/session tokens and cookies are updated and persisted.
5. A webservice map is stored and used by service clients to call concrete iCloud endpoints.

Service usage flow:

1. Authenticate once.
2. Resolve service root URL from the webservice map.
3. Instantiate the relevant service client from `pyicloud/services/`.
4. Service client methods execute endpoint-specific requests and map responses back to models/helpers.

## Test layout

- `tests/test_*.py`: behavior-focused tests by module/domain.
- `tests/const_*.py`: reusable fixtures/constants for mocked Apple responses.
- `tests/mock.py`: test doubles for service/session behavior.
- `tests/conftest.py`: shared pytest fixtures.

## Pull request expectations

- Keep changes focused and scoped.
- Add or update tests for behavior changes.
- Run the local quality checks before opening a PR.
- Update docs when user-facing behavior or contributor workflow changes.
