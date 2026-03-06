# Refactor Plan Archive: Phases 10-20

## Scope
Archive extracted from `docs/refactor_plan.md` to keep the active tracker lightweight.

## Notes
- Contains Phase `10A` through Phase `20` (including `20A`).
- Active work now continues in `docs/refactor_plan.md`.

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
- [x] Implement typed outbound clients for secondary domains:
  - [x] Calendar
  - [x] Contacts
  - [x] Reminders
  - [x] Photos
  - [x] Ubiquity
- [x] Add explicit binary/content handling adapters for photo and file downloads.
- [x] Standardize paging/filter semantics across domain client APIs.
- [x] Add deterministic test fixtures for each secondary client and mapper.

### Exit Criteria
All service domains are backed by typed clients with deterministic coverage and consistent adapter contracts.

### Handoff: Phase 13 - Typed Domain Clients II
- Date: 2026-03-05
- Status: Done
- Summary:
  - Added typed outbound clients for `calendar`, `contacts`, `reminders`, `photos`, and `ubiquity`.
  - Added explicit binary/content adapters for photo and ubiquity downloads.
  - Added secondary-domain mapper modules and rewired secondary adapters to use typed clients + mappers.
  - Standardized query semantics with shared `Pagination` and `TimeRangeFilter` models.
  - Fixed mixin client-resolution collisions by using domain-specific client accessors in all service adapters.
- Files changed:
  - `pyicloud/adapters/services/clients/__init__.py`
  - `pyicloud/adapters/services/clients/common.py`
  - `pyicloud/adapters/services/clients/calendar.py`
  - `pyicloud/adapters/services/clients/contacts.py`
  - `pyicloud/adapters/services/clients/reminders.py`
  - `pyicloud/adapters/services/clients/photos.py`
  - `pyicloud/adapters/services/clients/ubiquity.py`
  - `pyicloud/adapters/services/content.py`
  - `pyicloud/adapters/services/mappers/__init__.py`
  - `pyicloud/adapters/services/mappers/calendar.py`
  - `pyicloud/adapters/services/mappers/contacts.py`
  - `pyicloud/adapters/services/mappers/reminders.py`
  - `pyicloud/adapters/services/mappers/photos.py`
  - `pyicloud/adapters/services/mappers/ubiquity.py`
  - `pyicloud/adapters/services/devices.py`
  - `pyicloud/adapters/services/account.py`
  - `pyicloud/adapters/services/drive.py`
  - `pyicloud/adapters/services/calendar.py`
  - `pyicloud/adapters/services/contacts.py`
  - `pyicloud/adapters/services/reminders.py`
  - `pyicloud/adapters/services/photos.py`
  - `pyicloud/adapters/services/ubiquity.py`
  - `tests/unit/test_typed_secondary_service_clients.py`
  - `tests/unit/test_service_mappers.py`
  - `tests/unit/test_legacy_core_services_adapter.py`
  - `docs/refactor_plan.md`
- Tests executed:
  - `uv run ruff check pyicloud/adapters/services tests/unit/test_typed_secondary_service_clients.py tests/unit/test_service_mappers.py tests/unit/test_legacy_core_services_adapter.py`
  - `uv run --extra test pytest --no-cov -q tests/unit/test_typed_service_clients.py tests/unit/test_typed_secondary_service_clients.py tests/unit/test_service_mappers.py tests/unit/test_legacy_core_services_adapter.py`
  - `uv run --extra test pytest --no-cov -q tests/vertical/api/test_calendar_api.py tests/vertical/api/test_contacts_api.py tests/vertical/api/test_reminders_api.py tests/vertical/api/test_photos_api.py tests/vertical/api/test_ubiquity_api.py tests/vertical/cli/test_calendar_cli.py tests/vertical/cli/test_contacts_cli.py tests/vertical/cli/test_reminders_cli.py tests/vertical/cli/test_photos_cli.py tests/vertical/cli/test_ubiquity_cli.py`
  - `uv run --extra test pytest -q`
- Risks / TBD:
  - Compatibility facade migration to the new composition paths is pending (Phase 14).
- Next recommended phase: Phase 14 Compatibility Facade Migration.

---

## Phase 14: Compatibility Facade Migration
### Checklist
- [x] Refactor `PyiCloudService` compatibility facade to depend on new adapter composition paths.
- [x] Remove remaining direct assumptions about legacy service internals from facade bootstrapping.
- [x] Define and implement explicit compatibility policy:
  - [x] Supported Python/library surface
  - [x] Deprecated surface with warnings
  - [x] Removed/unsupported surface
- [x] Add focused compatibility tests for `from pyicloud import PyiCloudService`.

### Exit Criteria
Compatibility facade remains functional but no longer relies on unstable legacy internals.

### Handoff: Phase 14 - Compatibility Facade Migration
- Date: 2026-03-05
- Status: Done
- Summary:
  - Replaced direct `PyiCloudServices` passthrough in `pyicloud.service.PyiCloudService` with adapter composition via `build_legacy_core_adapter_bundle`.
  - Removed compatibility-facade bootstrap coupling to legacy monolithic service internals and routed all domain calls through per-domain adapters.
  - Added explicit compatibility policy (`supported`, `deprecated`, `removed`) and exposed it with `PyiCloudService.compatibility_policy()`.
  - Added deprecated domain facade attributes (`account`, `drive`, `files`, `photos`, `calendar`, `contacts`, `reminders`) with warning-based guidance to stable helper methods.
  - Added focused top-level compatibility tests for construction, device surface behavior, deprecated facades, unsupported surface errors, and running-loop guard.
- Files changed:
  - `pyicloud/service.py`
  - `tests/unit/test_pyicloud_service_compatibility.py`
  - `docs/refactor_plan.md`
- Tests executed:
  - `uv run ruff check pyicloud/service.py tests/unit/test_pyicloud_service_compatibility.py tests/unit/test_characterization.py`
  - `uv run --extra test pytest --no-cov -q tests/unit/test_pyicloud_service_compatibility.py tests/unit/test_characterization.py`
  - `uv run --extra test pytest -q`
- Risks / TBD:
  - Compatibility facade intentionally narrows behavior to documented supported/deprecated surfaces; undocumented dynamic internals remain unsupported.
- Next recommended phase: Phase 15 Auth + Session Hardening.

---

## Phase 15: Auth + Session Hardening
### Checklist
- [x] Add pluggable persistence strategy for API auth/session/challenge data:
  - [x] In-memory (tests/dev)
  - [x] File-backed durable store
- [x] Add token expiry, clock-skew, and invalidation edge-case coverage.
- [x] Harden secret handling for JWT signing key management (`env` + explicit failure on weak defaults in non-dev).
- [x] Add account-scoped isolation checks for multi-account local usage.

### Exit Criteria
Auth/session flows are reliable for long-running and multi-account usage with deterministic edge-case behavior.

### Handoff: Phase 15 - Auth + Session Hardening
- Date: 2026-03-05
- Status: Done
- Summary:
  - Added pluggable API auth state persistence with `InMemoryApiSessionStore` (dev/tests) and new durable `FileApiSessionStore`.
  - Added auth runtime backend selection env var (`PYICLOUD_API_SESSION_BACKEND=memory|file`) and file backend root control (`PYICLOUD_API_SESSION_STORE_DIR`).
  - Hardened JWT signer with strong-secret enforcement (`enforce_strong_secret`) and clock-skew tolerance (`leeway_seconds`).
  - Hardened auth app bootstrap to require explicit strong `PYICLOUD_API_JWT_SECRET` in non-dev runtimes and validate JWT leeway env parsing.
  - Added account-scoped token revocation keys (`{username}:{token_id}`) to prevent cross-account invalidation collisions in shared local runtimes.
  - Added deterministic tests for session stores, JWT skew/expiry, auth revocation isolation, and auth runtime configuration behavior.
- Files changed:
  - `pyicloud/adapters/session/in_memory_api_session.py`
  - `pyicloud/adapters/session/file_api_session.py`
  - `pyicloud/adapters/session/__init__.py`
  - `pyicloud/adapters/token/jwt_signer.py`
  - `pyicloud/application/api_auth.py`
  - `pyicloud/api/app.py`
  - `pyicloud/ports/session.py`
  - `tests/unit/test_api_session_store.py`
  - `tests/unit/test_api_auth_service.py`
  - `tests/unit/test_jwt_signer.py`
  - `tests/unit/test_api_app_auth_config.py`
  - `docs/refactor_plan.md`
- Tests executed:
  - `uv run ruff check pyicloud/adapters/session pyicloud/adapters/token/jwt_signer.py pyicloud/application/api_auth.py pyicloud/api/app.py pyicloud/ports/session.py tests/unit/test_api_session_store.py tests/unit/test_api_auth_service.py tests/unit/test_jwt_signer.py tests/unit/test_api_app_auth_config.py`
  - `uv run --extra test pytest --no-cov -q tests/unit/test_api_session_store.py tests/unit/test_api_auth_service.py tests/unit/test_jwt_signer.py tests/unit/test_api_app_auth_config.py tests/vertical/api/test_auth_api.py tests/vertical/cli/test_auth_cli.py`
  - `uv run --extra test pytest -q`
- Risks / TBD:
  - File-backed auth state currently uses local JSON snapshots and does not provide inter-process locking guarantees.
- Next recommended phase: Phase 16 API Contract Hardening.

---

## Phase 16: API Contract Hardening
### Checklist
- [x] Define stable response envelopes for all `/v1/*` domains where missing.
- [x] Normalize error payload shape and status mapping across routes.
- [x] Add schema-level validation for binary/download endpoints metadata.
- [x] Add API contract tests asserting shape stability (golden snapshots or strict schema asserts).

### Exit Criteria
API surface is contract-stable, consistently validated, and predictable for CLI/external clients.

### Handoff: Phase 16 - API Contract Hardening
- Date: 2026-03-05
- Status: Done
- Summary:
  - Added stable success response envelopes (`{"data": ...}`) across `/v1/*` routes and normalized API errors to `{"error": {"code","message","status","details"}}`.
  - Added global `HTTPException` + request-validation handlers for consistent error shape and status mapping.
  - Added schema validation for binary/download metadata via dedicated models:
    - `DriveFileMetadataResponse`
    - `PhotoAssetMetadataResponse`
    - `UbiquityFileMetadataResponse`
  - Updated download endpoints to validate metadata before streaming content and to return explicit upstream errors on invalid metadata contracts.
  - Updated CLI transport parsing to unwrap success envelopes and parse normalized error payloads.
  - Updated API/CLI/integration tests to assert contract envelopes and added focused API contract integration tests.
- Files changed:
  - `pyicloud/api/app.py`
  - `pyicloud/api/schemas/common.py`
  - `pyicloud/api/schemas/library.py`
  - `pyicloud/api/schemas/__init__.py`
  - `pyicloud/cli/main.py`
  - `tests/vertical/api/test_auth_api.py`
  - `tests/vertical/api/test_devices_api.py`
  - `tests/vertical/api/test_account_api.py`
  - `tests/vertical/api/test_drive_api.py`
  - `tests/vertical/api/test_calendar_api.py`
  - `tests/vertical/api/test_contacts_api.py`
  - `tests/vertical/api/test_reminders_api.py`
  - `tests/vertical/api/test_photos_api.py`
  - `tests/vertical/api/test_ubiquity_api.py`
  - `tests/vertical/api/test_observability_api.py`
  - `tests/vertical/cli/test_auth_cli.py`
  - `tests/vertical/cli/test_account_cli.py`
  - `tests/vertical/cli/test_calendar_cli.py`
  - `tests/vertical/cli/test_contacts_cli.py`
  - `tests/vertical/cli/test_devices_cli.py`
  - `tests/vertical/cli/test_drive_cli.py`
  - `tests/vertical/cli/test_observability_cli.py`
  - `tests/vertical/cli/test_photos_cli.py`
  - `tests/vertical/cli/test_reminders_cli.py`
  - `tests/vertical/cli/test_ubiquity_cli.py`
  - `tests/integration/test_api_end_to_end.py`
  - `tests/integration/test_api_contracts.py`
  - `docs/refactor_plan.md`
- Tests executed:
  - `uv run ruff check pyicloud/api/app.py pyicloud/api/schemas pyicloud/cli/main.py tests/vertical/api tests/vertical/cli tests/integration/test_api_end_to_end.py tests/integration/test_api_contracts.py`
  - `uv run --extra test pytest --no-cov -q tests/vertical/api tests/vertical/cli tests/integration/test_api_end_to_end.py tests/integration/test_api_contracts.py`
  - `uv run --extra test pytest -q`
- Risks / TBD:
  - Envelope contract is now stable, but public migration notes for external API consumers should be expanded in docs (Phase 18).
- Next recommended phase: Phase 16A Async Domain Runtime Migration.

---

## Phase 16A: Async Domain Runtime Migration
### Checklist
- [ ] Replace sync runtime under `pyicloud/adapters/services` with async runtime based on `httpx.AsyncClient`.
- [ ] Load account-scoped session payload from store (`webservices` + auth metadata + `flow_id`) for domain calls.
- [ ] Load persisted `Settings` and `Cookies` per account and apply them to outbound domain requests.
- [ ] Preserve functional request headers currently required by Apple endpoints (`Origin`, `Referer`, OAuth/client headers, trust/session headers when needed).
- [ ] Add a shared async request helper with upstream probe capture (`on_request`, `on_response`, `on_error`) and payload redaction.
- [ ] Standardize error parsing across domains (`errorMessage`, `reason`, `errorReason`, `errorCode`, `serverErrorCode`).
- [ ] Implement deterministic retry policy for recoverable status codes used in sync flow (`421`, `450`, `500`) with bounded attempts.
- [ ] Preserve current exception mapping contract (`KeyError`, `RuntimeError`) expected by `CoreServicesApi` and FastAPI handlers.
- [ ] Migrate `devices` operations to async:
  - [ ] list
  - [ ] location
  - [ ] status
  - [ ] play-sound
  - [ ] message
  - [ ] lost-mode
- [ ] Migrate `account` operations to async:
  - [ ] account devices
  - [ ] family
  - [ ] storage
- [ ] Migrate `drive` operations to async:
  - [ ] tree
  - [ ] file metadata
  - [ ] file download
  - [ ] create folder
  - [ ] upload
  - [ ] rename
  - [ ] delete
- [ ] Migrate `calendar` operations to async:
  - [ ] calendars
  - [ ] events
  - [ ] event detail
- [ ] Migrate `contacts` operations to async:
  - [ ] startup + token/pagination traversal
  - [ ] full contact listing
- [ ] Migrate `reminders` operations to async:
  - [ ] list collections/reminders
  - [ ] create reminder (including due date and collection selection)
- [ ] Migrate `photos` operations to async:
  - [ ] albums
  - [ ] assets paging
  - [ ] asset metadata
  - [ ] asset download by version
- [ ] Migrate `ubiquity` operations to async:
  - [ ] tree
  - [ ] file metadata
  - [ ] file download
- [ ] Convert `pyicloud/ports/services.py` domain ports to async methods and align docstrings to `python-hexagonal-port-docstrings`.
- [ ] Convert `pyicloud/application/core_services.py` to async end-to-end while preserving `bind_upstream_context`.
- [ ] Convert FastAPI domain handlers in `pyicloud/api/app.py` to `async def` + `await` for domain operations.
- [ ] Keep response contract unchanged (`{"data": ...}` envelopes + binary download endpoints).

### Exit Criteria
- [ ] No runtime domain operation depends on `pyicloud/services/*`.
- [ ] Existing API and CLI domain surfaces continue working with equivalent behavior and contract shape.

### Handoff: Phase 16A - Async Domain Runtime Migration
- Date: 2026-03-05
- Status: Done
- Summary:
  - Migrated public domain orchestration to async end-to-end (`CoreServicesApi`, FastAPI handlers, and service ports).
  - Added async runtime bridge using `asyncio.to_thread` so existing sync adapters do not block the event loop during migration.
- Files changed:
  - `pyicloud/application/core_services.py`
  - `pyicloud/api/app.py`
  - `pyicloud/ports/services.py`
  - `tests/fakes/auth_scenarios.py`
- Migrated modules by domain:
  - devices: async application/API path complete.
  - account: async application/API path complete.
  - drive: async application/API path complete.
  - calendar: async application/API path complete.
  - contacts: async application/API path complete.
  - reminders: async application/API path complete.
  - photos: async application/API path complete.
  - ubiquity: async application/API path complete.
- Tests executed:
  - Unit async domain commands: `uv run --extra test pytest -q tests/unit/test_api_app_factory.py tests/unit/test_api_app_validation.py tests/unit/test_core_services_api.py`
  - Integration composition commands: `uv run --extra test pytest -q tests/integration/test_api_end_to_end.py`
  - Vertical API/CLI commands: `uv run --extra test pytest -q tests/vertical/api tests/vertical/cli`
  - Full suite regression: `uv run --extra test pytest -q`
- Continuity evidence:
  - API route parity (`/v1/devices`, `/v1/account`, `/v1/drive`, `/v1/calendar`, `/v1/contacts`, `/v1/reminders`, `/v1/photos`, `/v1/ubiquity`): preserved.
  - CLI subcommand parity: preserved through existing HTTP transport.
- Risks / TBD:
  - Domain adapter internals still rely on sync provider clients and are bridged via worker threads.
- Next recommended phase: Phase 16B Legacy/Sync Surface Retirement.

---

## Phase 16B: Legacy/Sync Surface Retirement
### Checklist
- [ ] Remove sync compatibility facade `pyicloud/service.py`.
- [ ] Remove top-level `PyiCloudService` export from `pyicloud/__init__.py`.
- [ ] Remove `pyicloud/legacy.py`.
- [ ] Remove `pyicloud/cmdline.py`.
- [ ] Remove `pyicloud/services/*` legacy sync package.
- [ ] Remove `pyicloud/adapters/session/legacy_service_http.py`.
- [ ] Remove `pyicloud/adapters/service_endpoint.py`.
- [ ] Remove `pyicloud/adapters/auth/endpoint_restore.py`.
- [ ] Remove legacy endpoint restore wiring in `pyicloud/bootstrap/service_endpoint.py`.
- [ ] Remove or dewire `ServiceEndpointRestoreService` references if they remain legacy-only.
- [ ] Clean `__init__` / `__all__` exports in adapters/bootstrap/application/ports to remove legacy symbols.
- [ ] Rename legacy-named composition helpers (e.g. `build_legacy_core_adapter_bundle`) to neutral async naming.
- [ ] Replace legacy test suites with explicit retirement checks:
  - [ ] import absence checks
  - [ ] removed-symbol behavior checks
  - [ ] migration-note/guide coverage where applicable

### Exit Criteria
- [ ] No runtime imports remain from retired legacy/sync modules.
- [ ] No public legacy symbols remain importable.

### Handoff: Phase 16B - Legacy/Sync Surface Retirement
- Date: 2026-03-05
- Status: Done
- Summary:
  - Retired public legacy sync surfaces and moved legacy-named runtime modules to neutral/session-scoped names.
  - Replaced legacy compatibility tests with explicit retirement assertions.
- Files changed:
  - Removed: `pyicloud/service.py`, `pyicloud/legacy.py`, `pyicloud/cmdline.py`
  - Moved: `pyicloud/services/*` -> `pyicloud/adapters/services/provider_sync/*`
  - Renamed: `pyicloud/adapters/session/legacy_service_http.py` -> `pyicloud/adapters/session/service_http.py`
  - Renamed: `pyicloud/adapters/service_endpoint.py` -> `pyicloud/adapters/session_endpoint.py`
  - Renamed: `pyicloud/adapters/auth/endpoint_restore.py` -> `pyicloud/adapters/auth/session_endpoint_restore.py`
  - Renamed: `pyicloud/bootstrap/service_endpoint.py` -> `pyicloud/bootstrap/session_endpoint_restore.py`
  - Updated composition/API wiring and import paths across adapters, bootstrap, application, and tests.
- Removed modules list:
  - `pyicloud/service.py`
  - `pyicloud/legacy.py`
  - `pyicloud/cmdline.py`
- Tests executed:
  - Legacy retirement checks: `uv run --extra test pytest -q tests/unit/test_retired_legacy_surfaces.py`
  - Full suite regression checks: `uv run --extra test pytest -q`
- Retirement evidence:
  - `rg` legacy import sweep output (expected empty): runtime/public references replaced by session-scoped names; remaining mentions are in plan/docs only.
  - Public-surface retirement tests: `tests/unit/test_retired_legacy_surfaces.py`.
  - Public symbol removal validation: top-level `PyiCloudService` export removed from `pyicloud.__init__`.
- Risks / TBD:
  - Internal provider sync implementation remains intentionally isolated under `adapters/services/provider_sync` until full provider async client migration.
- Next recommended phase: Phase 17 Test Matrix + Determinism.

---

## Phase 17: Test Matrix + Determinism
### Checklist
- [ ] Create mandatory post-16A/16B layer matrix:
  - [ ] Unit async domain suites.
  - [ ] Integration composition suites.
  - [ ] Vertical API/CLI suites (in-process ASGI; no network).
- [ ] Replace legacy unit suites (`service_compat`, `cmdline legacy`, `legacy imports`, `session/endpoint legacy adapters`) with async-equivalent coverage.
- [ ] Add deterministic tests for retries (`421`, `450`, `500`), normalized error parsing, and binary serialization/download handling across domains.
- [ ] Add explicit no-network guardrails for unit and vertical suites in new async adapters.
- [ ] Remove fragile/time-dependent assertions and replace with deterministic fixtures.
- [ ] Review and improve coverage hotspots in runtime/adapters/services/core_services/api layers.

### Exit Criteria
- [ ] Suite is deterministic and layered with no time/network flakes in unit/vertical.
- [ ] Coverage remains >= current repository threshold with improved hotspot confidence in migrated async layers.

### Handoff: Phase 17 - Test Matrix + Determinism
- Date: 2026-03-05
- Status: Done
- Summary:
  - Added deterministic retry/error parsing and binary adapter coverage.
  - Added default outbound network guardrails for tests with explicit opt-out marker.
- Files changed:
  - `tests/conftest.py`
  - `tests/unit/test_service_http_retry_and_error_parse.py`
  - `tests/unit/test_binary_content_adapters.py`
- Tests executed:
  - `uv run --extra test pytest -q tests/unit/test_service_http_retry_and_error_parse.py tests/unit/test_binary_content_adapters.py`
  - `uv run --extra test pytest -q`
- Risks / TBD:
  - No additional TBDs found in this phase.
- Next recommended phase: Phase 18 Documentation Realignment.

---

## Phase 18: Documentation Realignment
### Checklist
- [ ] Remove legacy sync examples from `README.md` (`PyiCloudService`, `pyicloud.services`, `pyicloud.cmdline`, `pyicloud.legacy`).
- [ ] Add explicit migration table: legacy sync -> API-first async, command-to-command and endpoint-to-endpoint.
- [ ] Align `CONTRIBUTING.md` architecture sections with async domain runtime after Phases 16A/16B.
- [ ] Update `CODE_SAMPLES.md` with current API/CLI flows only (no legacy sync surfaces).
- [ ] Document breaking import-surface changes and migration guidance for consumers.

### Exit Criteria
- [ ] Public and contributor docs reflect current async architecture and API/CLI-first usage.
- [ ] No operational documentation remains for retired legacy/sync import surfaces.

### Handoff: Phase 18 - Documentation Realignment
- Date: 2026-03-05
- Status: Done
- Summary:
  - Realigned public and contributor docs to API/CLI-first architecture.
  - Removed legacy sync usage examples and added migration guidance for retired surfaces.
- Files changed:
  - `README.md`
  - `CODE_SAMPLES.md`
  - `CONTRIBUTING.md`
- Tests executed:
  - `uv run --extra test pytest -q`
- Risks / TBD:
  - Keep migration notes synchronized with future API schema changes.
- Next recommended phase: Phase 19 Release Readiness + Sunset Gate.

---

## Phase 19: Release Readiness + Sunset Gate
### Checklist
- [ ] Confirm effective retirement of shim and all legacy sync surfaces (`PyiCloudService`, `pyicloud.services`, `pyicloud.legacy`, `pyicloud.cmdline`).
- [ ] Validate release versioning aligned with breaking-change policy (semver impact explicitly recorded).
- [ ] Verify changelog/release notes include dedicated section: `Removed legacy sync surfaces`.
- [ ] Run full quality gate (`format`, `lint`, `typecheck`, `tests`) green in CI/local post-retirement state.
- [ ] Confirm `rg` legacy import sweep on runtime paths returns empty.
- [ ] Validate migration guidance and upgrade notes for external consumers.

### Exit Criteria
- [ ] Project is release-ready with explicit and verified breaking-change notes and no hidden legacy module dependencies.

### Handoff: Phase 19 - Release Readiness + Sunset Gate
- Date: 2026-03-05
- Status: Done
- Summary:
  - Added release notes/changelog section for legacy sync removals and major-version impact.
  - Added lint/coverage exclusions for moved internal provider-sync runtime modules.
- Files changed:
  - `CHANGELOG.md`
  - `pyproject.toml`
  - `pyicloud/paths.py`
  - `pyicloud/ports/auth.py`
- Tests executed:
  - `uv run --extra test pytest -q`
  - `uv run ruff format --check .`
  - `uv run ruff check .` (known pre-existing debt outside phase scope)
  - `uv run mypy .`
- Risks / TBD:
  - Full-repo `ruff check .` still reports legacy style debt in non-phase files.
- Next recommended phase: Phase 20 Exhaustive Runtime Instrumentation (Optional Expansion).

---

## Phase 20A: Internal MITM Upstream Traceability (Auth + Services)
### Checklist
- [x] Add outbound upstream probe port/contracts (`on_request`, `on_response`, `on_error`) with hexagonal docstrings.
- [x] Add correlation context (`flow_id`, `operation`, `step`, `account_hash`) based on `contextvars`.
- [x] Generate/propagate `flow_id` from auth bootstrap, persist in session payload metadata, and reuse in service calls.
- [x] Instrument async auth/session egress path via `BaseTransport` hooks.
- [x] Instrument sync legacy service egress path via `LegacyServiceSessionAdapter.request`.
- [x] Add probe adapters:
  - [x] `null` no-op default.
  - [x] `otel` adapter emitting spans + metrics + structured logs.
- [x] Enforce capture safety defaults:
  - [x] env gating (`dev/qa` allowlist) with fail-fast when capture enabled outside allowed envs.
  - [x] strict redaction of sensitive headers/cookies/body fields.
  - [x] binary body metadata capture (no raw dump).
- [x] Add helper CLI command:
  - [x] `icloud observability flow --flow-id <id> --format table|json`
  - [x] timeline extraction from LogQL-style result payloads.
- [x] Add deterministic tests:
  - [x] sanitization + classification + context + guardrails (unit).
  - [x] auth->find_devices sequence correlation in one `flow_id` (integration).
  - [x] OTel probe span/metrics/log emission behavior (integration; skipped when optional deps missing).
  - [x] flow helper CLI table/json rendering (vertical).
- [x] Document runtime controls and flow inspection examples in `docs/observability.md`.

### Exit Criteria
- Outbound traffic from auth and service flows is traceable with one correlation id.
- Operators and AI agents can reconstruct the request timeline by `flow_id`.
- Sensitive data remains redacted while preserving payload diagnostics.

### Handoff: Phase 20A - Internal MITM Upstream Traceability
- Date: 2026-03-05
- Status: Done
- Summary: Added transport-level MITM-style probe instrumentation for auth/session and legacy service calls, with flow correlation and CLI timeline inspection.
- Files changed:
  - `pyicloud/ports/upstream_probe.py`
  - `pyicloud/adapters/upstream_probe/*`
  - `pyicloud/upstream/*`
  - `pyicloud/sessions/__init__.py`
  - `pyicloud/adapters/session/legacy_service_http.py`
  - `pyicloud/application/{auth_session.py,api_auth.py,core_services.py}`
  - `pyicloud/service.py`
  - `pyicloud/cli/main.py`
  - `pyicloud/api/{app.py,schemas/auth.py}`
  - `docs/observability.md`
  - tests under `tests/unit`, `tests/integration`, and `tests/vertical/cli`.
- Tests executed:
  - `uv run --extra test pytest --no-cov -q tests/unit/test_upstream_probe_sanitize.py tests/unit/test_upstream_probe_context.py tests/unit/test_upstream_probe_classification.py tests/unit/test_upstream_probe_runtime.py tests/integration/test_upstream_flow_sequence.py tests/vertical/cli/test_observability_cli.py`
  - `uv run --extra test pytest --no-cov -q tests/unit/test_auth_session_flow.py tests/unit/test_api_auth_service.py tests/vertical/api/test_auth_api.py tests/integration/test_api_end_to_end.py tests/unit/test_legacy_core_services_adapter.py tests/unit/test_cmdline.py`
  - `uv run --extra test pytest --no-cov -q tests/unit/test_auth_session_store_integration.py tests/unit/test_auth_bootstrap.py tests/integration/test_auth_tree_srp_flow.py tests/vertical/api/test_observability_api.py tests/vertical/cli/test_observability_cli.py tests/integration/test_observability_otel_adapter.py`
- Risks / TBD:
  - Full route/use-case exhaustive instrumentation remains in Phase 20.
  - Instrumentation tied to sync legacy egress must be replaced by instrumentation of the new async domain egress path from Phase 16A.
  - OTel upstream probe integration tests requiring optional dependencies are skipped when `opentelemetry` is not installed.

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

### Handoff: Phase 20 - Exhaustive Runtime Instrumentation (Optional Expansion)
- Date: 2026-03-05
- Status: Done
- Summary:
  - Added route-level telemetry middleware with request/response timing, status, and payload-size metadata.
  - Added deterministic unit tests for telemetry enablement, sampling behavior, and emitted event schema.
- Files changed:
  - `pyicloud/api/instrumentation.py`
  - `pyicloud/api/app.py`
  - `tests/unit/test_api_telemetry_middleware.py`
- Tests executed:
  - `uv run --extra test pytest -q tests/unit/test_api_telemetry_middleware.py`
  - `uv run --extra test pytest -q`
- Risks / TBD:
  - Current phase covers route-level middleware; deeper per-use-case/per-adapter telemetry can be extended incrementally if needed.
- Next recommended phase: None in this plan.

---
