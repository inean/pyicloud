# Refactor Plan: Ports/Adapters + FastAPI + API-Driven CLI

## Resume Protocol (read this first)
1. Read this file fully.
2. Run baseline: `uv run --extra test pytest -q`.
3. Continue the first phase marked `In Progress`.
4. Do not start a new phase until this file is updated with completion evidence for the current one.

## Decision Snapshot (locked)
- First cycle scope: Auth + Account + Find My iPhone + Drive.
- CLI model: subcommands only.
- Compatibility policy: soft compatibility for Python/library surfaces; no guarantee for old flat CLI flags.
- CLI transport: HTTP-first.
- API naming: domain-first.
- API versioning: `/v1`.
- Token format: JWT HS256 via PyJWT.
- Token persistence: file store + env override.
- Vertical tests: in-process ASGI only; no iCloud network calls.
- Legacy removal boundary: core auth/session/endpoint legacy first; service internals migrate incrementally.
- Observability query scope: PromQL, TraceQL, and LogQL.
- Observability backend policy: project must run without observability dependencies via `null` adapters; `otel` adapter remains optional.

## Phase Board
- Planned:
  - Phase 13 Typed Domain Clients II
  - Phase 14 Compatibility Facade Migration
  - Phase 15 Auth + Session Hardening
  - Phase 16 API Contract Hardening
  - Phase 17 Test Matrix + Determinism
  - Phase 18 Documentation Realignment
  - Phase 19 Release Readiness + Sunset Gate
  - Phase 20 Exhaustive Runtime Instrumentation (Optional Expansion)
- In Progress:
  - None
- Done:
  - Phase 0 Artifact Bootstrap
  - Phase 1 Architecture Skeleton + Guardrails
  - Phase 2 Auth Vertical Slice (Fake First)
  - Phase 3 Real Auth Adapter + Core Legacy Auth Replacement
  - Phase 4 Devices Vertical Slice
  - Phase 5 Account Vertical Slice
  - Phase 6 Drive Vertical Slice
  - Phase 7 CLI Consolidation
  - Phase 8 Secondary Services I
  - Phase 9 Secondary Services II
  - Phase 10 Legacy Cleanup + Hardening
  - Phase 10A Observability Query Abstraction (PromQL/TraceQL/LogQL)
  - Phase 11 Core Adapter Decomposition
  - Phase 12 Typed Domain Clients I
- Blocked:
  - None

## Handoff Template (append after each phase)
```md
### Handoff: Phase X - <name>
- Date:
- Status: Done | In Progress | Blocked
- Summary:
- Files changed:
- Tests executed:
- Risks / TBD:
- Next recommended phase:
```

---

## Phase 0: Artifact Bootstrap
### Checklist
- [x] Create canonical plan file at `docs/refactor_plan.md`.
- [x] Add decision snapshot.
- [x] Add phase board.
- [x] Add handoff template.
- [x] Add resume protocol with exact commands.

### Exit Criteria
Plan file exists and is self-contained enough for a pristine session to continue implementation.

### Handoff: Phase 0 - Artifact Bootstrap
- Date: 2026-03-04
- Status: Done
- Summary: Created canonical implementation tracker with locked decisions and continuity protocol.
- Files changed: `docs/refactor_plan.md`
- Tests executed: None (documentation-only phase).
- Risks / TBD: None.
- Next recommended phase: Phase 1 Architecture Skeleton + Guardrails.

---

## Phase 1: Architecture Skeleton + Guardrails
### Checklist
- [x] Add API package skeleton (`pyicloud/api/*`).
- [x] Add CLI package skeleton (`pyicloud/cli/*`).
- [x] Add new ports for token/session and core services.
- [x] Add shared domain/API error models.
- [x] Add network-blocking fixture for vertical tests.
- [x] Add characterization coverage for:
  - [x] top-level `PyiCloudService` import gap
  - [x] proxy attribute forwarding bug
  - [x] CLI lost-mode option mapping bug

### Exit Criteria
Skeleton compiles; guardrail tests exist; baseline remains green or improved.

### Handoff: Phase 1 - Architecture Skeleton + Guardrails
- Date: 2026-03-04
- Status: Done
- Summary: Added initial architectural scaffolding, guardrail tests, and compatibility surface fixes.
- Files changed: see git diff
- Tests executed: `uv run --extra test pytest -q` (post-Phase 1)
- Risks / TBD: API vertical behavior still pending; core service endpoints not fully wired.
- Next recommended phase: Phase 2 Auth Vertical Slice (Fake First).

---

## Phase 2: Auth Vertical Slice (Fake First)
### Checklist
- [x] Implement deterministic fake scenario auth adapter:
  - [x] success (no 2FA)
  - [x] success (2FA required)
  - [x] invalid credentials
  - [x] invalid security code
  - [x] expired session
- [x] Implement `/v1/auth/*` routes:
  - [x] `POST /v1/auth/login`
  - [x] `POST /v1/auth/security-code`
  - [x] `GET /v1/auth/session`
  - [x] `POST /v1/auth/logout`
- [x] Implement JWT signer adapter (HS256, PyJWT) and session/challenge store.
- [x] Implement `icloud auth` CLI subcommands using HTTP API.
- [x] Persist CLI token in file store with env override.
- [x] Add vertical tests for CLI -> API -> fake auth adapter.

### Exit Criteria
Auth works end-to-end without any iCloud network dependency.

### Handoff: Phase 2 - Auth Vertical Slice (Fake First)
- Date: 2026-03-04
- Status: Done
- Summary: Implemented auth API routes, JWT/token-challenge ports+adapters, fake scenario auth adapter, API-first auth CLI, and vertical tests (API + CLI) with no external network.
- Files changed:
  - `pyicloud/api/*`
  - `pyicloud/cli/main.py`
  - `pyicloud/application/api_auth.py`
  - `pyicloud/ports/session.py`
  - `pyicloud/adapters/token/jwt_signer.py`
  - `pyicloud/adapters/session/in_memory_api_session.py`
  - `pyicloud/adapters/auth/fake_scenario_auth.py`
  - `tests/vertical/*`
  - `tests/fakes/auth_scenarios.py`
- Tests executed:
  - `uv run --extra test pytest -q tests/vertical/api/test_auth_api.py tests/vertical/cli/test_auth_cli.py`
  - `uv run --extra test pytest -q`
- Risks / TBD:
  - Challenge/token store is currently in-memory only (single-process runtime).
  - No refresh-token flow yet.
- Next recommended phase: Phase 3 Real Auth Adapter + Core Legacy Auth Replacement.

---

## Phase 3: Real Auth Adapter + Core Legacy Auth Replacement
### Checklist
- [x] Wire real auth path to existing tree auth/session sequence.
- [x] Keep fake path for deterministic vertical tests.
- [x] Replace runtime dependency on legacy auth/session endpoint restoration flow where possible.
- [x] Add/keep Python compatibility facade (`from pyicloud import PyiCloudService`).
- [x] Add deprecation warnings for compatibility surface.

### Exit Criteria
Real auth path preserved, fake auth path retained for tests, compatibility facade functional.

### Handoff: Phase 3 - Real Auth Adapter + Core Legacy Auth Replacement
- Date: 2026-03-04
- Status: Done
- Summary:
  - Real auth path is wired through `AuthApiService` default factory using tree-based auth (`build_auth_session_service`).
  - Fake auth path remains active for vertical tests.
  - Added compatibility facade `pyicloud.service.PyiCloudService` and exported it from `pyicloud.__init__`.
  - Added deprecation warning on compatibility facade initialization.
  - Replaced default runtime endpoint restoration wiring in core adapters and legacy compatibility flows with direct session-store + endpoint-factory composition.
- Files changed:
  - `pyicloud/adapters/auth/legacy_cli_auth.py`
  - `pyicloud/adapters/auth/__init__.py`
  - `pyicloud/adapters/services/legacy_core.py`
  - `pyicloud/cmdline.py`
  - `tests/unit/test_legacy_cli_auth_adapter.py`
  - `tests/unit/test_legacy_core_services_adapter.py`
  - `tests/unit/test_cmdline.py`
  - `docs/refactor_plan.md`
- Tests executed:
  - `uv run --extra test pytest -q tests/unit/test_legacy_cli_auth_adapter.py tests/unit/test_cmdline.py tests/unit/test_legacy_core_services_adapter.py`
  - `uv run --extra test pytest -q`
- Risks / TBD:
  - Device/account/drive runtime still relies on legacy service implementation internals (`PyiCloudServices`, `LegacyServiceSessionAdapter`) pending later cleanup phases.
  - Compatibility facade currently authenticates synchronously with `asyncio.run`.
- Next recommended phase: Phase 4 Devices Vertical Slice (add deterministic fake builders + vertical tests).

---

## Phase 4: Devices Vertical Slice
### Checklist
- [x] Add device ports + adapters for list/location/status/sound/message/lost mode.
- [x] Add `/v1/devices*` routes.
- [x] Add `icloud devices` subcommands.
- [x] Add deterministic fake data builders and vertical tests.

### Exit Criteria
Full existing Find My iPhone operations exposed via API and CLI.

### Handoff: Phase 4 - Devices Vertical Slice
- Date: 2026-03-04
- Status: Done
- Summary:
  - Added deterministic device fixtures in vertical fake core services and wired them as default vertical app dependencies.
  - Added API vertical coverage for device listing, location/status retrieval, action commands, and not-found behavior.
  - Added CLI vertical coverage for `icloud devices` subcommands against in-process ASGI API transport.
- Files changed:
  - `tests/fakes/auth_scenarios.py`
  - `tests/vertical/conftest.py`
  - `tests/vertical/api/test_devices_api.py`
  - `tests/vertical/cli/test_devices_cli.py`
  - `docs/refactor_plan.md`
- Tests executed:
  - `uv run --extra test pytest -q tests/vertical/api/test_auth_api.py tests/vertical/api/test_devices_api.py tests/vertical/cli/test_auth_cli.py tests/vertical/cli/test_devices_cli.py`
  - `uv run --extra test pytest -q`
- Risks / TBD:
  - Account and Drive vertical slices still rely on placeholder deterministic core outputs and need dedicated vertical suites.
- Next recommended phase: Phase 5 Account Vertical Slice (add deterministic vertical tests).

---

## Phase 5: Account Vertical Slice
### Checklist
- [x] Add account query ports + adapters (devices/family/storage).
- [x] Add `/v1/account/*` routes.
- [x] Add `icloud account` subcommands.
- [x] Add deterministic vertical tests.

### Exit Criteria
Account parity via API/CLI with no live network calls.

### Handoff: Phase 5 - Account Vertical Slice
- Date: 2026-03-04
- Status: Done
- Summary:
  - Extended deterministic vertical fake core services with account device/family/storage fixtures.
  - Added API vertical coverage for `/v1/account/devices`, `/v1/account/family`, and `/v1/account/storage`.
  - Added CLI vertical coverage for `icloud account devices|family|storage`.
- Files changed:
  - `tests/fakes/auth_scenarios.py`
  - `tests/vertical/api/test_account_api.py`
  - `tests/vertical/cli/test_account_cli.py`
  - `docs/refactor_plan.md`
- Tests executed:
  - `uv run --extra test pytest -q tests/vertical/api/test_auth_api.py tests/vertical/api/test_devices_api.py tests/vertical/api/test_account_api.py tests/vertical/cli/test_auth_cli.py tests/vertical/cli/test_devices_cli.py tests/vertical/cli/test_account_cli.py`
  - `uv run --extra test pytest -q`
- Risks / TBD:
  - Drive vertical slice still needs deterministic fake coverage for tree/file/mutate/download behavior.
- Next recommended phase: Phase 6 Drive Vertical Slice (add deterministic vertical tests including streaming/download behavior).

---

## Phase 6: Drive Vertical Slice
### Checklist
- [x] Add drive ports + adapters (tree/file/upload/mkdir/rename/delete).
- [x] Add `/v1/drive/*` routes.
- [x] Add `icloud drive` subcommands.
- [x] Add deterministic vertical tests including streaming/download behavior.

### Exit Criteria
Drive parity via API/CLI with no live network calls.

### Handoff: Phase 6 - Drive Vertical Slice
- Date: 2026-03-04
- Status: Done
- Summary:
  - Added deterministic in-memory drive fixtures and mutation behavior to vertical fake core services.
  - Added API vertical coverage for drive tree/file metadata, binary download, mkdir/upload/rename/delete.
  - Added CLI vertical coverage for `icloud drive` commands including `--download-to` and upload flow.
- Files changed:
  - `tests/fakes/auth_scenarios.py`
  - `tests/vertical/api/test_drive_api.py`
  - `tests/vertical/cli/test_drive_cli.py`
  - `docs/refactor_plan.md`
- Tests executed:
  - `uv run --extra test pytest -q tests/vertical`
  - `uv run --extra test pytest -q`
- Risks / TBD:
  - Old flat CLI behavior remains; migration/help messaging still pending in Phase 7.
- Next recommended phase: Phase 7 CLI Consolidation.

---

## Phase 7: CLI Consolidation
### Checklist
- [x] Retire old flat CLI behavior.
- [x] Ensure `icloud` points to new subcommand CLI.
- [x] Add migration/help messaging.

### Exit Criteria
Only subcommand CLI remains and is API-first.

### Handoff: Phase 7 - CLI Consolidation
- Date: 2026-03-04
- Status: Done
- Summary:
  - Replaced `pyicloud.cmdline` runtime behavior with a compatibility shim that retires flat flags and emits explicit migration guidance.
  - Added concrete old->new command mappings in migration text for device/account/drive workflows.
  - Updated cmdline and characterization tests to assert deprecation and migration messaging behavior.
- Files changed:
  - `pyicloud/cmdline.py`
  - `tests/unit/test_cmdline.py`
  - `tests/unit/test_characterization.py`
  - `docs/refactor_plan.md`
- Tests executed:
  - `uv run --extra test pytest -q tests/unit/test_cmdline.py tests/unit/test_characterization.py tests/vertical`
  - `uv run --extra test pytest -q`
- Risks / TBD:
  - Legacy Python compatibility facade (`PyiCloudService`) remains until later cleanup phases.
- Next recommended phase: Phase 8 Secondary Services I.

---

## Phase 8: Secondary Services I
### Checklist
- [x] Add Calendar, Contacts, Reminders ports/adapters/routes/CLI.
- [x] Add deterministic vertical tests.

### Exit Criteria
All three domains reachable and tested via API/CLI.

### Handoff: Phase 8 - Secondary Services I
- Date: 2026-03-04
- Status: Done
- Summary:
  - Added Calendar/Contacts/Reminders outbound ports, application façade wiring, and legacy-backed adapters.
  - Added `/v1/calendar/*`, `/v1/contacts`, and `/v1/reminders` endpoints plus reminder create schema.
  - Added API-first CLI subcommands for `icloud calendar`, `icloud contacts`, and `icloud reminders`.
  - Extended deterministic vertical fake core services with secondary-service fixtures and reminder mutation behavior.
  - Added vertical API/CLI coverage and extended integration flow assertions for all three domains.
- Files changed:
  - `pyicloud/ports/services.py`
  - `pyicloud/ports/__init__.py`
  - `pyicloud/application/core_services.py`
  - `pyicloud/adapters/services/legacy_core.py`
  - `pyicloud/api/app.py`
  - `pyicloud/api/schemas/reminders.py`
  - `pyicloud/api/schemas/__init__.py`
  - `pyicloud/cli/main.py`
  - `tests/fakes/auth_scenarios.py`
  - `tests/vertical/api/test_calendar_api.py`
  - `tests/vertical/api/test_contacts_api.py`
  - `tests/vertical/api/test_reminders_api.py`
  - `tests/vertical/cli/test_calendar_cli.py`
  - `tests/vertical/cli/test_contacts_cli.py`
  - `tests/vertical/cli/test_reminders_cli.py`
  - `tests/integration/test_api_end_to_end.py`
  - `docs/refactor_plan.md`
- Tests executed:
  - `uv run --extra test pytest --no-cov -q tests/vertical/api/test_calendar_api.py tests/vertical/api/test_contacts_api.py tests/vertical/api/test_reminders_api.py tests/vertical/cli/test_calendar_cli.py tests/vertical/cli/test_contacts_cli.py tests/vertical/cli/test_reminders_cli.py`
  - `uv run --extra test pytest -q`
- Risks / TBD:
  - Photos and Ubiquity domains remain for Phase 9.
  - Secondary-service adapter coverage is currently mostly via vertical/integration paths; unit tests are still sparse.
- Next recommended phase: Phase 9 Secondary Services II.

---

## Phase 9: Secondary Services II
### Checklist
- [x] Add Photos + Ubiquity ports/adapters/routes/CLI.
- [x] Add deterministic vertical tests.

### Exit Criteria
Remaining library service functionality exposed through API/CLI.

### Handoff: Phase 9 - Secondary Services II
- Date: 2026-03-04
- Status: Done
- Summary:
  - Added Photos/Ubiquity outbound ports with skill-aligned method docstrings and wired them through `CoreServicesApi`.
  - Extended legacy core adapter with photo album/asset metadata+download operations and ubiquity tree/file metadata+download operations.
  - Added `/v1/photos/*` and `/v1/ubiquity/*` domain-first API routes plus API-first CLI command groups `icloud photos` and `icloud ubiquity`.
  - Extended deterministic vertical fake core services with photos and ubiquity fixtures, including binary download behavior.
  - Added vertical API/CLI suites for both domains and unit coverage for the new legacy adapter paths.
- Files changed:
  - `pyicloud/ports/services.py`
  - `pyicloud/ports/__init__.py`
  - `pyicloud/application/core_services.py`
  - `pyicloud/adapters/services/legacy_core.py`
  - `pyicloud/api/app.py`
  - `pyicloud/cli/main.py`
  - `tests/fakes/auth_scenarios.py`
  - `tests/vertical/api/test_photos_api.py`
  - `tests/vertical/api/test_ubiquity_api.py`
  - `tests/vertical/cli/test_photos_cli.py`
  - `tests/vertical/cli/test_ubiquity_cli.py`
  - `tests/unit/test_legacy_core_services_adapter.py`
  - `tests/integration/test_api_end_to_end.py`
  - `docs/refactor_plan.md`
- Tests executed:
  - `uv run --extra test pytest --no-cov -q tests/vertical/api/test_photos_api.py tests/vertical/api/test_ubiquity_api.py tests/vertical/cli/test_photos_cli.py tests/vertical/cli/test_ubiquity_cli.py`
  - `uv run --extra test pytest -q`
- Risks / TBD:
  - Photos and ubiquity endpoints currently focus on read/list/download; deeper mutation/management flows remain unmodeled.
  - `LegacyCoreServicesAdapter` still contains broad legacy coupling slated for Phase 10 cleanup.
- Next recommended phase: Phase 10 Legacy Cleanup + Hardening.

---

## Phase 10: Legacy Cleanup + Hardening
### Checklist
- [x] Remove legacy modules no longer needed:
  - [x] `pyicloud/adapters/auth/legacy_cli_auth.py`
  - [x] `pyicloud/services/endpoint_adapter.py`
  - [x] `pyicloud/services/session_adapter.py`
- [x] Remove dead compatibility branches while preserving supported facade.
- [x] Update docs/contributing architecture references.
- [x] Run full suite and vertical suite green.

### Exit Criteria
Core legacy auth/session coupling removed, docs aligned, test suites green.

### Handoff: Phase 10 - Legacy Cleanup + Hardening
- Date: 2026-03-04
- Status: Done
- Summary:
  - Removed legacy auth/session endpoint modules and replaced them with adapter-layer modules:
    - `pyicloud/adapters/auth/endpoint_restore.py`
    - `pyicloud/adapters/service_endpoint.py`
    - `pyicloud/adapters/session/legacy_service_http.py`
  - Rewired compatibility and restore composition paths to the new adapter modules while preserving `PyiCloudService` facade behavior.
  - Updated unit tests to the new module locations and kept behavior checks intact.
  - Updated `CONTRIBUTING.md` architecture references for API-first runtime and new compatibility adapter locations.
- Files changed:
  - `pyicloud/adapters/auth/legacy_cli_auth.py` (removed)
  - `pyicloud/services/endpoint_adapter.py` (removed)
  - `pyicloud/services/session_adapter.py` (removed)
  - `pyicloud/adapters/auth/endpoint_restore.py`
  - `pyicloud/adapters/service_endpoint.py`
  - `pyicloud/adapters/session/legacy_service_http.py`
  - `pyicloud/adapters/auth/__init__.py`
  - `pyicloud/adapters/session/__init__.py`
  - `pyicloud/bootstrap/service_endpoint.py`
  - `pyicloud/adapters/services/legacy_core.py`
  - `tests/unit/test_legacy_cli_auth_adapter.py`
  - `tests/unit/test_endpoint_adapter.py`
  - `tests/unit/test_session_adapter.py`
  - `CONTRIBUTING.md`
  - `docs/refactor_plan.md`
- Tests executed:
  - `uv run --extra test pytest --no-cov -q tests/unit/test_legacy_cli_auth_adapter.py tests/unit/test_endpoint_adapter.py tests/unit/test_session_adapter.py tests/unit/test_auth_bootstrap.py tests/unit/test_service_endpoint_restore.py tests/unit/test_legacy_core_services_adapter.py`
  - `uv run --extra test pytest --no-cov -q tests/vertical`
  - `uv run --extra test pytest -q`
- Risks / TBD:
  - Remaining compatibility logic still depends on legacy synchronous service client internals (`pyicloud/services/*`) through the facade and `LegacyCoreServicesAdapter`.
  - Additional simplification of `LegacyCoreServicesAdapter` is possible in future cleanup cycles but is outside this plan.
- Next recommended phase: Phase 10A Observability Query Abstraction (PromQL/TraceQL/LogQL).

---

## Phase 10A: Observability Query Abstraction (PromQL/TraceQL/LogQL)
### Checklist
- [x] Add observability query ports and domain contracts:
  - [x] Add `pyicloud/ports/observability.py` with protocol ports for PromQL, TraceQL, and LogQL query execution.
  - [x] Add request/response TypedDicts (or pydantic domain models) for:
    - [x] instant query
    - [x] range query
    - [x] result envelope (`status`, `language`, `data`, `warnings`, `source`)
  - [x] Add domain-level query errors (backend unavailable, unsupported query mode, execution failure) and map them in API.
  - [x] Apply skill-aligned port docstrings (`Direction`, `Purpose`, `Implemented by`) plus method-level caller/boundary/raises sections.
- [x] Implement default no-dependency adapter:
  - [x] Add `pyicloud/adapters/observability/null.py` implementing all observability ports.
  - [x] Return deterministic, non-failing "unconfigured" envelopes so the project works without any backend technology.
  - [x] Ensure null adapter is the default in application/bootstrap wiring.
- [x] Implement optional OTel ecosystem adapter:
  - [x] Add `pyicloud/adapters/observability/otel.py` with lazy imports so base install has zero OTel dependency.
  - [x] Support backend endpoint configuration via env vars for PromQL/TraceQL/LogQL query APIs.
  - [x] Add optional tracing spans around backend calls when OTel packages are installed.
  - [x] Fail fast with clear startup error only when `otel` adapter is explicitly selected but optional deps are missing.
- [x] Add packaging and composition wiring:
  - [x] Add optional dependency group `otel` in `pyproject.toml`.
  - [x] Add adapter selection env var(s), defaulting to `null`.
  - [x] Wire new observability service(s) in `pyicloud/api/app.py` factory without affecting existing auth/core services.
- [x] Expose API + CLI surfaces:
  - [x] Add `/v1/observability/promql`, `/v1/observability/traceql`, `/v1/observability/logql` endpoints.
  - [x] Add request/response schemas under `pyicloud/api/schemas/`.
  - [x] Keep canonical API/CLI query language names (`promql`, `traceql`, `logql`) with no misspelled alias support.
  - [x] Add `icloud observability promql|traceql|logql` subcommands.
- [x] Add deterministic test coverage:
  - [x] Unit: null adapter behavior, otel adapter configuration/errors, query request normalization.
  - [x] Vertical: API + CLI round trips using null adapter with external network blocked.
  - [x] Integration: otel adapter using mocked backend endpoints (no live external calls).
  - [x] Guardrail: no direct imports from optional OTel packages outside `adapters/observability/otel.py`.
- [x] Update docs:
  - [x] Add setup and env-var examples for null vs otel adapter modes.
  - [x] Document response envelopes and error mapping for observability query endpoints.

### Exit Criteria
- Project boots and all existing tests pass without installing any OTel or backend-specific dependencies.
- Observability endpoints and CLI commands return deterministic null-adapter results by default.
- Installing `.[otel]` and selecting `otel` adapter enables real backend query execution for PromQL/TraceQL/LogQL.
- Optional dependency boundaries are enforced and covered by tests.

### Handoff: Phase 10A - Observability Query Abstraction (PromQL/TraceQL/LogQL)
- Date: 2026-03-05
- Status: Done
- Summary:
  - Added observability ports/contracts and domain query errors with skill-aligned port docstrings.
  - Added default `null` adapter and optional `otel` adapter with lazy OTel imports and fail-fast dependency check when explicitly selected.
  - Wired `ObservabilityApi` into FastAPI app factory with adapter mode/env configuration.
  - Added `/v1/observability/{promql|traceql|logql}` and CLI commands `icloud observability promql|traceql|logql`.
  - Added deterministic unit/vertical/integration coverage and an OTel import guardrail test.
  - Added observability documentation with setup, env vars, envelope format, and error mapping.
- Files changed:
  - `pyicloud/ports/observability.py`
  - `pyicloud/domain/api_errors.py`
  - `pyicloud/domain/__init__.py`
  - `pyicloud/application/observability.py`
  - `pyicloud/application/__init__.py`
  - `pyicloud/adapters/observability/*`
  - `pyicloud/api/app.py`
  - `pyicloud/api/schemas/observability.py`
  - `pyicloud/api/schemas/__init__.py`
  - `pyicloud/cli/main.py`
  - `pyicloud/ports/__init__.py`
  - `pyproject.toml`
  - `docs/observability.md`
  - `tests/unit/test_observability_application.py`
  - `tests/unit/test_observability_null_adapter.py`
  - `tests/unit/test_observability_otel_adapter.py`
  - `tests/unit/test_no_direct_otel_imports.py`
  - `tests/vertical/api/test_observability_api.py`
  - `tests/vertical/cli/test_observability_cli.py`
  - `tests/integration/test_observability_otel_adapter.py`
  - `docs/refactor_plan.md`
- Tests executed:
  - `uv run --extra test pytest --no-cov -q tests/unit/test_observability_application.py tests/unit/test_observability_null_adapter.py tests/unit/test_observability_otel_adapter.py tests/unit/test_no_direct_otel_imports.py tests/vertical/api/test_observability_api.py tests/vertical/cli/test_observability_cli.py tests/integration/test_observability_otel_adapter.py`
  - `uv run --extra test pytest -q`
- Risks / TBD:
  - OTel adapter currently uses generic HTTP query execution; backend-specific advanced query capabilities remain for future hardening.
  - Observability instrumentation outside query adapter boundaries (domain-level metrics/log spans across all services) is still pending.
- Next recommended phase: Phase 11 Core Adapter Decomposition.

---

## Phase 11: Core Adapter Decomposition
### Checklist
- [x] Split `LegacyCoreServicesAdapter` into domain adapters:
  - [x] `DevicesServiceAdapter`
  - [x] `AccountServiceAdapter`
  - [x] `DriveServiceAdapter`
  - [x] `CalendarServiceAdapter`
  - [x] `ContactsServiceAdapter`
  - [x] `RemindersServiceAdapter`
  - [x] `PhotosServiceAdapter`
  - [x] `UbiquityServiceAdapter`
- [x] Introduce a thin composition root that wires adapters without domain logic.
- [x] Keep existing API/CLI behavior unchanged while replacing internals.
- [x] Add/expand unit tests per adapter module and shared helper coverage.

### Exit Criteria
No monolithic core adapter remains; domain adapters are independently testable and behavior parity is preserved.

### Handoff: Phase 11 - Core Adapter Decomposition
- Date: 2026-03-05
- Status: Done
- Summary:
  - Extracted domain adapters into dedicated modules (`devices`, `account`, `drive`, `calendar`, `contacts`, `reminders`, `photos`, `ubiquity`) with a shared legacy runtime.
  - Converted `LegacyCoreServicesAdapter` into a thin compatibility facade that composes the shared runtime and inherits domain adapter behavior.
  - Added explicit composition root `build_legacy_core_adapter_bundle` and rewired API app factory to inject per-domain adapters into `CoreServicesApi`.
  - Updated port documentation `Implemented by` references to reflect decomposed adapters.
  - Expanded unit coverage to validate runtime restoration behavior plus decomposed adapter/composition behavior.
- Files changed:
  - `pyicloud/adapters/services/runtime.py`
  - `pyicloud/adapters/services/devices.py`
  - `pyicloud/adapters/services/account.py`
  - `pyicloud/adapters/services/drive.py`
  - `pyicloud/adapters/services/calendar.py`
  - `pyicloud/adapters/services/contacts.py`
  - `pyicloud/adapters/services/reminders.py`
  - `pyicloud/adapters/services/photos.py`
  - `pyicloud/adapters/services/ubiquity.py`
  - `pyicloud/adapters/services/composition.py`
  - `pyicloud/adapters/services/legacy_core.py`
  - `pyicloud/adapters/services/__init__.py`
  - `pyicloud/api/app.py`
  - `pyicloud/ports/services.py`
  - `tests/unit/test_legacy_core_services_adapter.py`
  - `docs/refactor_plan.md`
- Tests executed:
  - `uv run --extra test pytest --no-cov -q tests/unit/test_legacy_core_services_adapter.py`
  - `uv run --extra test pytest --no-cov -q tests/vertical/api/test_drive_api.py tests/vertical/api/test_devices_api.py tests/vertical/api/test_account_api.py`
  - `uv run --extra test pytest -q`
- Risks / TBD:
  - Adapter-specific unit suites can still grow (particularly devices/drive/reminders edge cases) to increase hotspot confidence.
- Next recommended phase: Phase 12 Typed Domain Clients I.

---

## Phase 12: Typed Domain Clients I
### Checklist
- [x] Implement typed outbound clients for high-traffic domains:
  - [x] Find My iPhone (`devices`)
  - [x] Account
  - [x] Drive
- [x] Move provider payload normalization from adapters into dedicated mapper modules.
- [x] Ensure adapters depend on typed clients/interfaces, not on broad `PyiCloudServices` objects.
- [x] Add contract-oriented tests for mappers and client request/response handling.

### Exit Criteria
Devices/account/drive flows run through typed clients and explicit mappers, with no direct domain logic embedded in endpoint glue.

### Handoff: Phase 12 - Typed Domain Clients I
- Date: 2026-03-05
- Status: Done
- Summary:
  - Added typed outbound clients for `devices`, `account`, and `drive` under `pyicloud/adapters/services/clients/`.
  - Added dedicated mapper modules under `pyicloud/adapters/services/mappers/` and moved normalization logic out of adapters.
  - Rewired `DevicesServiceAdapter`, `AccountServiceAdapter`, and `DriveServiceAdapter` to depend on typed clients + mappers instead of directly operating on broad `PyiCloudServices` payloads.
  - Added unit contract coverage for typed clients and mappers and validated behavior parity through existing adapter and vertical suites.
- Files changed:
  - `pyicloud/adapters/services/clients/__init__.py`
  - `pyicloud/adapters/services/clients/devices.py`
  - `pyicloud/adapters/services/clients/account.py`
  - `pyicloud/adapters/services/clients/drive.py`
  - `pyicloud/adapters/services/mappers/__init__.py`
  - `pyicloud/adapters/services/mappers/devices.py`
  - `pyicloud/adapters/services/mappers/account.py`
  - `pyicloud/adapters/services/mappers/drive.py`
  - `pyicloud/adapters/services/devices.py`
  - `pyicloud/adapters/services/account.py`
  - `pyicloud/adapters/services/drive.py`
  - `tests/unit/test_typed_service_clients.py`
  - `tests/unit/test_service_mappers.py`
  - `tests/unit/test_legacy_core_services_adapter.py`
  - `docs/refactor_plan.md`
- Tests executed:
  - `uv run --extra test pytest --no-cov -q tests/unit/test_typed_service_clients.py tests/unit/test_service_mappers.py`
  - `uv run --extra test pytest --no-cov -q tests/unit/test_legacy_core_services_adapter.py`
  - `uv run --extra test pytest --no-cov -q tests/vertical/api/test_devices_api.py tests/vertical/api/test_account_api.py tests/vertical/api/test_drive_api.py tests/vertical/cli/test_devices_cli.py tests/vertical/cli/test_account_cli.py tests/vertical/cli/test_drive_cli.py`
  - `uv run --extra test pytest -q`
- Risks / TBD:
  - Typed clients for secondary domains are pending in Phase 13.
- Next recommended phase: Phase 13 Typed Domain Clients II.

---

## Phase 13: Typed Domain Clients II
### Checklist
- [ ] Implement typed outbound clients for secondary domains:
  - [ ] Calendar
  - [ ] Contacts
  - [ ] Reminders
  - [ ] Photos
  - [ ] Ubiquity
- [ ] Add explicit binary/content handling adapters for photo and file downloads.
- [ ] Standardize paging/filter semantics across domain client APIs.
- [ ] Add deterministic test fixtures for each secondary client and mapper.

### Exit Criteria
All service domains are backed by typed clients with deterministic coverage and consistent adapter contracts.

---

## Phase 14: Compatibility Facade Migration
### Checklist
- [ ] Refactor `PyiCloudService` compatibility facade to depend on new adapter composition paths.
- [ ] Remove remaining direct assumptions about legacy service internals from facade bootstrapping.
- [ ] Define and implement explicit compatibility policy:
  - [ ] Supported Python/library surface
  - [ ] Deprecated surface with warnings
  - [ ] Removed/unsupported surface
- [ ] Add focused compatibility tests for `from pyicloud import PyiCloudService`.

### Exit Criteria
Compatibility facade remains functional but no longer relies on unstable legacy internals.

---

## Phase 15: Auth + Session Hardening
### Checklist
- [ ] Add pluggable persistence strategy for API auth/session/challenge data:
  - [ ] In-memory (tests/dev)
  - [ ] File-backed durable store
- [ ] Add token expiry, clock-skew, and invalidation edge-case coverage.
- [ ] Harden secret handling for JWT signing key management (`env` + explicit failure on weak defaults in non-dev).
- [ ] Add account-scoped isolation checks for multi-account local usage.

### Exit Criteria
Auth/session flows are reliable for long-running and multi-account usage with deterministic edge-case behavior.

---

## Phase 16: API Contract Hardening
### Checklist
- [ ] Define stable response envelopes for all `/v1/*` domains where missing.
- [ ] Normalize error payload shape and status mapping across routes.
- [ ] Add schema-level validation for binary/download endpoints metadata.
- [ ] Add API contract tests asserting shape stability (golden snapshots or strict schema asserts).

### Exit Criteria
API surface is contract-stable, consistently validated, and predictable for CLI/external clients.

---

## Phase 17: Test Matrix + Determinism
### Checklist
- [ ] Add layered test matrix targets:
  - [ ] Unit (adapters/clients/mappers)
  - [ ] Vertical API/CLI (in-process ASGI, no network)
  - [ ] Integration composition tests
- [ ] Add dedicated no-network enforcement for all non-integration suites.
- [ ] Remove fragile/time-dependent assertions and replace with deterministic fixtures.
- [ ] Keep coverage >= 80% while improving hotspot coverage in adapters and compatibility layers.

### Exit Criteria
Test suite is deterministic, layered, and fast enough for iterative refactors without flaky regressions.

---

## Phase 18: Documentation Realignment
### Checklist
- [ ] Update `README.md` to prioritize API-first CLI and `/v1` service model.
- [ ] Update `CODE_SAMPLES.md` with current subcommand and API examples.
- [ ] Align `CONTRIBUTING.md` architecture sections with actual module layout after Phases 11-17.
- [ ] Add migration notes from legacy examples to API-first equivalents.

### Exit Criteria
Public and contributor docs accurately reflect current architecture and recommended usage patterns.

---

## Phase 19: Release Readiness + Sunset Gate
### Checklist
- [ ] Run full quality gate (`format`, `lint`, `typecheck`, `tests`) green in CI/local.
- [ ] Confirm no imports remain from retired legacy modules.
- [ ] Validate deprecation warnings and migration guidance messaging.
- [ ] Decide sunset milestone for compatibility shim behavior (`pyicloud/cmdline.py`) and document timeline.
- [ ] Cut release notes for completed migration cycle.

### Exit Criteria
Project is release-ready with explicit compatibility sunset criteria and no hidden legacy module dependencies.

---

## Phase 20: Exhaustive Runtime Instrumentation (Optional Expansion)
### Checklist
- [ ] Define telemetry contract for full-code instrumentation:
  - [ ] Span naming conventions for API routes, application use-cases, and adapters.
  - [ ] Stable metric names, units, and label sets with cardinality budgets.
  - [ ] Structured log schema (`timestamp`, `level`, `message`, `trace_id`, `span_id`, `request_id`, `component`).
- [ ] Instrument all API routes under `/v1/*`:
  - [ ] Request count, latency histogram, and error count by route/method/status.
  - [ ] Per-route payload size metrics (request/response) where practical.
  - [ ] Route-level trace spans with route template attributes (not raw unbounded paths).
- [ ] Instrument all application use-cases/facades:
  - [ ] Auth flows (`login`, `security-code`, `session`, `logout`) with outcome tags.
  - [ ] Core services use-cases (devices/account/drive/calendar/contacts/reminders/photos/ubiquity).
  - [ ] Observability query use-cases (PromQL/TraceQL/LogQL) with backend, mode, and outcome.
- [ ] Instrument outbound adapters and infrastructure boundaries:
  - [ ] HTTP client spans/metrics for provider and observability backend calls.
  - [ ] Retry/failure counters and latency distributions for external calls.
  - [ ] Explicit redaction/sanitization of secrets and PII in logs and span attributes.
- [ ] Add runtime controls:
  - [ ] Env-configurable sampling, enable/disable switches, and safe defaults for local/dev/CI.
  - [ ] Backpressure/fallback behavior when telemetry exporters are unavailable.
- [ ] Add deterministic verification:
  - [ ] Unit tests for telemetry wrappers/decorators and attribute mapping.
  - [ ] Integration tests with in-memory exporters asserting spans/metrics/log records for representative flows.
  - [ ] Guardrails preventing high-cardinality labels and unsafe payload logging.
- [ ] Add model-operator documentation:
  - [ ] Query cookbook for PromQL/TraceQL/LogQL to inspect route/use-case health.
  - [ ] Dashboards and alert examples aligned with emitted metrics/logs/traces.

### Exit Criteria
- All API routes and application use-cases emit consistent traces, metrics, and structured logs.
- Telemetry is observable end-to-end in deterministic tests without leaking secrets or high-cardinality labels.
- Operators (and models) can inspect behavior using documented PromQL/TraceQL/LogQL queries and dashboards.

## Next Session Start Here
```bash
cd /Users/inean/Projects/Legacy/Sandbox/pyicloud
uv run --extra test pytest -q
# Continue Phase 13 from docs/refactor_plan.md
```
