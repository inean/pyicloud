# Refactor Plan Archive: Phases 20-30

## Scope
Archive extracted from `docs/refactor_plan.md` to keep the active tracker lightweight.

## Notes
- Contains Phase `21` through Phase `30`.
- Active work now continues in `docs/refactor_plan.md`.

---

## Phase 21: Challenge-Driven API + Credential Hygiene
### Goal
Implement the locked challenge-driven behavior: client tries normal operation first; backend detects expired Apple session and responds with an auth challenge that is completed via backend-mediated flow (`client -> backend -> Apple`).

### Checklist
- [x] Define and freeze challenge response contract for expired upstream sessions:
  - [x] Error code: `auth_challenge_required`.
  - [x] Challenge payload fields: `challenge_id`, `challenge_type`, `account_id`, `flow_id`, `expires_at`, `next_step`, `retryable`.
  - [x] Deterministic HTTP semantics (status code + headers) for all protected `/v1/*` domain endpoints.
- [x] Add challenge mapping in API layer for upstream auth/session expiration conditions:
  - [x] Map Apple/session expiration signals (`401`/`421`/`450` or equivalent domain errors) to challenge response.
  - [x] Preserve existing non-auth upstream error mapping (`502`, `503`, etc.).
- [x] Add challenge lifecycle operations in auth API:
  - [x] Start/resume challenge (from domain failure context).
  - [x] Submit credential step (if required by policy).
  - [x] Submit security-code/trust step.
  - [x] Complete challenge and return renewed API session context.
- [x] Remove plaintext credentials from challenge persistence:
  - [x] No `password` in challenge payload at any layer.
  - [x] Store opaque, minimal challenge context only.
  - [x] Add redaction and serialization safety tests for challenge state.
- [x] Add deterministic test coverage:
  - [x] Vertical: domain call -> challenge response.
  - [x] Vertical: challenge completion -> operation retry success.
  - [x] Unit: challenge payload schema and expiry behavior.

### Exit Criteria
- [x] Every protected domain route returns challenge envelope (not generic auth failure) on expired Apple session.
- [x] Challenge persistence contains no plaintext credentials (verified by tests + fixtures).
- [x] Contract documented in API schemas and examples.

### Handoff: Phase 21 - Challenge-Driven API + Credential Hygiene
- Date: 2026-03-06
- Status: Done
- Summary:
  - Added challenge-driven upstream-expiry mapping (`401`/`421`/`450`) to `auth_challenge_required` envelopes with deterministic details.
  - Added operation challenge issuance in `AuthApiService` and secure challenge persistence without plaintext passwords.
  - Updated security-code completion contract to require password input on completion rather than storing credentials in challenge payload.
- Files changed:
  - `pyicloud/application/api_auth.py`
  - `pyicloud/api/app.py`
  - `pyicloud/api/schemas/auth.py`
  - `pyicloud/cli/main.py`
  - `tests/unit/test_api_auth_service.py`
  - `tests/vertical/api/test_auth_api.py`
  - `tests/vertical/api/test_upstream_error_mapping.py`
  - `tests/vertical/cli/test_auth_cli.py`
  - `tests/integration/test_api_end_to_end.py`
- Tests executed:
  - `uv run --extra test pytest --no-cov -q tests/unit/test_api_auth_service.py tests/vertical/api/test_auth_api.py tests/vertical/api/test_upstream_error_mapping.py tests/vertical/cli/test_auth_cli.py`
  - `uv run --extra test pytest -q`
- Risks / TBD:
  - CLI automatic operation retry after challenge is pending in Phase 22.
- Next recommended phase: Phase 22 Challenge Execution Flow + CLI Auto-Retry.

---

## Phase 22: Challenge Execution Flow + CLI Auto-Retry
### Goal
Make CLI behavior truly challenge-driven and ergonomic: operation-first execution with backend challenge handling and controlled retry.

### Checklist
- [x] Add CLI challenge interceptor for protected commands:
  - [x] Attempt requested operation first.
  - [x] If response is `auth_challenge_required`, run challenge completion flow.
  - [x] Retry original operation once challenge is completed.
- [x] Define retry policy by command safety:
  - [x] Auto-retry for idempotent reads (`list`, `get`, `tree`, etc.).
  - [x] Explicit confirmation/flag for non-idempotent mutations where needed.
- [x] Keep transport model HTTP-first:
  - [x] CLI never talks to Apple directly.
  - [x] All challenge steps go through `/v1/auth/*`.
- [x] Improve UX and telemetry:
  - [x] Clear challenge prompts and progress states.
  - [x] Correlate original operation and challenge flow by one `flow_id`.
- [x] Add deterministic vertical tests:
  - [x] `icloud devices list` -> challenge -> success.
  - [x] `icloud drive tree` -> challenge -> success.
  - [x] Mutation command challenge behavior according to safety policy.

### Exit Criteria
- [x] CLI users can recover expired sessions without manually restarting full login flow.
- [x] Challenge flow is deterministic and covered in vertical tests.

### Handoff: Phase 22 - Challenge Execution Flow + CLI Auto-Retry
- Date: 2026-03-06
- Status: Done
- Summary:
  - Added CLI-side challenge interceptor that detects `auth_challenge_required`, executes backend-mediated auth completion, and retries the original command.
  - Implemented retry safety policy: automatic retry for read operations and explicit confirmation before retrying mutating operations.
  - Propagated challenge `flow_id` into login completion to keep operation/challenge correlation in backend telemetry context.
- Files changed:
  - `pyicloud/cli/main.py`
  - `pyicloud/api/schemas/auth.py`
  - `pyicloud/application/api_auth.py`
  - `pyicloud/api/app.py`
  - `tests/vertical/cli/test_auth_cli.py`
- Tests executed:
  - `uv run --extra test pytest --no-cov -q tests/vertical/cli/test_auth_cli.py tests/vertical/api/test_auth_api.py tests/unit/test_api_auth_service.py`
  - `uv run --extra test pytest -q`
- Risks / TBD:
  - Architectural boundary purification (application/import directions) remains pending in Phase 23.
- Next recommended phase: Phase 23 Layer Boundary Purification (Hexagonal).

---

## Phase 23: Layer Boundary Purification (Hexagonal)
### Goal
Enforce strict dependency direction across layers and remove known boundary leaks.

### Checklist
- [x] Remove `application -> bootstrap/trees/models` coupling in auth application services.
- [x] Replace concrete auth service construction inside `application` with injected ports/factories.
- [x] Remove `adapters -> cli` imports and invert control to composition/bootstrap.
- [x] Move composition/default wiring to dedicated bootstrap modules.
- [ ] Add architecture dependency rules:
  - [x] `domain` must not import `application/adapters/api/cli/bootstrap`.
  - [x] `application` must not import `adapters/api/cli/bootstrap/trees`.
  - [x] `adapters` must not import `cli`.
- [x] Add enforcement tests for forbidden imports and expected package boundaries.

### Exit Criteria
- [x] Import-sweep checks pass for all forbidden dependency directions.
- [x] Auth and challenge flows compile/run with boundary-compliant wiring only.

### Handoff: Phase 23 - Layer Boundary Purification (Hexagonal)
- Date: 2026-03-06
- Status: Done
- Summary:
  - Removed `application`-layer auth composition leakage by requiring injected auth service factories in `AuthApiService`.
  - Removed `adapters -> cli_auth` fallback import in legacy endpoint auth flow and enforced explicit runner injection.
  - Moved default API wiring (`auth/core/observability`) into dedicated bootstrap module `pyicloud/bootstrap/api_runtime.py`.
  - Added architecture boundary guard tests that block forbidden import directions for domain/application/adapters layers.
- Files changed:
  - `pyicloud/application/api_auth.py`
  - `pyicloud/api/app.py`
  - `pyicloud/bootstrap/api_runtime.py`
  - `pyicloud/bootstrap/__init__.py`
  - `pyicloud/adapters/auth/session_endpoint_restore.py`
  - `tests/unit/test_legacy_cli_auth_adapter.py`
  - `tests/unit/test_hexagonal_import_boundaries.py`
- Tests executed:
  - `uv run --extra test pytest --no-cov -q tests/unit/test_api_auth_service.py tests/vertical/api/test_auth_api.py tests/vertical/cli/test_auth_cli.py`
  - `uv run --extra test pytest --no-cov -q tests/unit/test_legacy_cli_auth_adapter.py tests/unit/test_service_endpoint_restore.py`
  - `uv run --extra test pytest --no-cov -q tests/unit/test_api_app_auth_config.py tests/unit/test_api_telemetry_middleware.py tests/vertical/api/test_auth_api.py tests/vertical/api/test_upstream_error_mapping.py tests/smoke/test_smoke.py`
  - `uv run --extra test pytest --no-cov -q tests/unit/test_hexagonal_import_boundaries.py tests/unit/test_api_app_auth_config.py tests/unit/test_legacy_cli_auth_adapter.py`
  - `uv run --extra test pytest -q`
- Risks / TBD:
  - API entrypoint (`pyicloud/api/app.py`) still centralizes routing/error handling; full module decomposition remains in Phase 25.
  - Async contract drift in service adapters remains pending in Phase 24.
- Next recommended phase: Phase 24 Async Port/Adapter Contract Convergence.

---

## Phase 24: Async Port/Adapter Contract Convergence
### Goal
Eliminate sync/async contract drift and align ports, adapters, and orchestration on one runtime model.

### Checklist
- [x] Normalize service adapter method signatures to match async port contracts.
- [x] Remove generic sync bridge behavior in application façade once adapters are async-consistent.
- [x] Decide and document runtime strategy:
  - [ ] Full async adapter implementation path.
  - [x] Transitional wrappers only where explicitly documented and bounded.
- [x] Add static contract verification:
  - [x] Protocol conformance checks for service adapters (`async` parity assertions by adapter/port pair).
  - [x] CI gate for async override compatibility.
- [x] Add regression tests for cancellation/timeouts/retries in async service paths.

### Exit Criteria
- [x] No async/sync override mismatches remain in service adapter layer.
- [x] Core service orchestration does not depend on implicit sync fallback behavior.

### Handoff: Phase 24 - Async Port/Adapter Contract Convergence
- Date: 2026-03-06
- Status: Done
- Summary:
  - Converted core service adapters (`devices/account/drive/calendar/contacts/reminders/photos/ubiquity`) to explicit `async` method signatures aligned with service ports.
  - Added bounded transitional runtime wrapper in adapter base (`_run_blocking`) so legacy sync provider clients run off-event-loop while preserving async contracts.
  - Removed generic sync bridge behavior from `CoreServicesApi` (`asyncio.to_thread` + mixed sync/awaitable branching), enforcing awaitable-only port calls.
  - Added deterministic guard tests for async contract parity and cancellation/timeout behavior in core service orchestration.
- Files changed:
  - `pyicloud/adapters/services/{account,calendar,contacts,devices,drive,photos,reminders,runtime,ubiquity}.py`
  - `pyicloud/application/core_services.py`
  - `tests/unit/test_legacy_core_services_adapter.py`
  - `tests/unit/test_core_services_async_contract.py`
- Tests executed:
  - `uv run --extra test pytest --no-cov -q tests/unit/test_legacy_core_services_adapter.py tests/unit/test_core_services_async_contract.py`
  - `uv run --extra test pytest --no-cov -q tests/unit/test_legacy_core_services_adapter.py tests/unit/test_core_services_async_contract.py tests/vertical/api/test_devices_api.py tests/vertical/api/test_account_api.py tests/vertical/api/test_drive_api.py tests/vertical/api/test_calendar_api.py tests/vertical/api/test_contacts_api.py tests/vertical/api/test_reminders_api.py tests/vertical/api/test_photos_api.py tests/vertical/api/test_ubiquity_api.py`
  - `uv run --extra test pytest -q`
- Risks / TBD:
  - Full async-native provider runtime migration is still pending (Phase 27); current phase intentionally uses bounded thread offloading wrappers over legacy sync provider clients.
  - Full mypy coverage for provider-sync internals remains constrained by existing untyped legacy module debt and should be tightened in Phase 26/27.
- Next recommended phase: Phase 25 API/CLI Decomposition + Typed Contracts.

---

## Phase 25: API/CLI Decomposition + Typed Contracts
### Goal
Reduce monolithic modules and replace dictionary-shaped cross-layer contracts with typed models.

### Checklist
- [x] Decompose API app module into:
  - [x] Composition/bootstrap wiring.
  - [x] Exception/response mapping.
  - [x] Domain routers.
  - [x] Dependency providers.
- [x] Decompose CLI module into command groups + shared transport/challenge middleware.
- [x] Introduce typed domain DTOs for high-traffic service contracts:
  - [x] devices/account/drive first.
  - [x] then calendar/contacts/reminders/photos/ubiquity.
- [x] Reduce `Mapping[str, Any]` / `Any` usage in ports and application façades.
- [x] Add serializer/mapper tests for typed contract compatibility.

### Exit Criteria
- [x] `api` and `cli` entry modules are thin composition shells.
- [x] Critical ports no longer rely on unbounded dict contracts.

### Handoff: Phase 25 - API/CLI Decomposition + Typed Contracts
- Date: 2026-03-06
- Status: Completed
- Summary:
  - Completed API decomposition by extracting remaining domain routers (`calendar/contacts/reminders/photos/ubiquity/observability`) and leaving `create_app` as composition + middleware + health wiring.
  - Completed CLI decomposition by extracting remaining command groups (`calendar/contacts/reminders/photos/ubiquity/observability`) and centralizing transport/challenge retry middleware in `pyicloud/cli/transport.py`.
  - Completed typed DTO rollout for `calendar/contacts/reminders/photos/ubiquity`, rewiring port signatures, adapters, mappers, and `CoreServicesApi` to typed contracts.
  - Extended DTO mapper compatibility tests with `pydantic.TypeAdapter` coverage for all service domains.
- Files changed:
  - `pyicloud/api/{app.py,dependencies.py,errors.py,responses.py}`
  - `pyicloud/api/routers/{__init__.py,auth.py,devices.py,account.py,drive.py,calendar.py,contacts.py,reminders.py,photos.py,ubiquity.py,observability.py}`
  - `pyicloud/cli/{main.py,token_store.py,transport.py,commands/*}`
  - `pyicloud/domain/{__init__.py,service_contracts.py}`
  - `pyicloud/ports/services.py`
  - `pyicloud/adapters/services/{account.py,devices.py,drive.py,calendar.py,contacts.py,reminders.py,photos.py,ubiquity.py}`
  - `pyicloud/adapters/services/mappers/{account.py,devices.py,drive.py,calendar.py,contacts.py,reminders.py,photos.py,ubiquity.py}`
  - `pyicloud/application/core_services.py`
  - `tests/unit/test_service_contract_dto_mappers.py`
- Tests executed:
  - `uv run --extra test pytest --no-cov -q tests/vertical/cli`
  - `uv run --extra test pytest --no-cov -q tests/unit/test_service_contract_dto_mappers.py tests/unit/test_service_mappers.py tests/unit/test_legacy_core_services_adapter.py tests/vertical/api/test_calendar_api.py tests/vertical/api/test_contacts_api.py tests/vertical/api/test_reminders_api.py tests/vertical/api/test_photos_api.py tests/vertical/api/test_ubiquity_api.py`
  - `uv run --extra test pytest --no-cov -q tests/vertical/api`
  - `uv run --extra test pytest -q`
- Risks / TBD:
  - None for this phase; continue with architecture guardrails and runtime containment in phases 26/27.
- Next recommended phase: Phase 26 (Architecture Guardrails + Quality Gate Hardening).

---

## Phase 26: Architecture Guardrails + Quality Gate Hardening
### Goal
Turn architecture expectations into enforceable automated checks and close current gate blind spots.

### Checklist
- [x] Add architecture test suite (forbidden imports + layer map assertions).
- [x] Add challenge-driven contract tests as non-optional gate.
- [x] Tighten static quality gates incrementally:
  - [x] Remove/ratchet lint exclusions around migrated service runtime files.
  - [x] Raise mypy coverage in adapters/services integration surface.
  - [x] Expand coverage targets to challenge and adapter runtime hotspots.
- [x] Add CI ratchet rules to prevent reintroduction of:
  - [x] plaintext credential persistence.
  - [x] legacy alias exports.
  - [x] sync adapter implementations for async ports.

### Exit Criteria
- [x] CI blocks architecture regressions by default.
- [x] Quality gates reflect real risk areas (not only easy surfaces).

### Handoff: Phase 26 - Architecture Guardrails + Quality Gate Hardening
- Date: 2026-03-06
- Status: Done
- Summary:
  - Expanded architecture guardrails with a layer-map matrix test and managed-layer assertions in `tests/unit/test_hexagonal_import_boundaries.py`.
  - Added non-optional challenge contract coverage across all protected service domains via `tests/integration/test_challenge_contract_gate.py` and wired explicit gate execution in CI (`unittests.yml`).
  - Added ratchet test for legacy alias exports (`tests/unit/test_legacy_alias_export_ratchet.py`) and explicit CI ratchet execution for credential persistence and async-port conformance.
  - Tightened hotspot quality gates with focused mypy enforcement (`--follow-imports=skip` on runtime/challenge modules) and a dedicated challenge/runtime coverage gate (`--cov-fail-under=82`) in `Makefile` and `coverage.yml`.
- Files changed:
  - `tests/unit/test_hexagonal_import_boundaries.py`
  - `tests/integration/test_challenge_contract_gate.py`
  - `tests/unit/test_legacy_alias_export_ratchet.py`
  - `.github/workflows/unittests.yml`
  - `.github/workflows/pythonlint.yml`
  - `.github/workflows/coverage.yml`
  - `Makefile`
  - `pyproject.toml`
  - `pyicloud/adapters/services/runtime.py`
- Tests executed:
  - `uv run --extra test pytest --no-cov -q tests/unit/test_hexagonal_import_boundaries.py`
  - `uv run --extra test pytest --no-cov -q tests/unit/test_hexagonal_import_boundaries.py tests/integration/test_challenge_contract_gate.py tests/unit/test_legacy_alias_export_ratchet.py tests/unit/test_api_auth_service.py::test_login_challenge_does_not_persist_plaintext_password tests/unit/test_core_services_async_contract.py::test_service_adapters_match_async_port_methods`
  - `uv run --extra lint mypy --follow-imports=skip pyicloud/application/api_auth.py pyicloud/application/core_services.py pyicloud/api/errors.py pyicloud/adapters/services/runtime.py`
  - `uv run --extra test pytest -q -o addopts='' --cov=pyicloud.application.api_auth --cov=pyicloud.api.errors --cov=pyicloud.adapters.services.runtime --cov=pyicloud.adapters.services --cov-report=term-missing --cov-fail-under=82 tests/integration/test_challenge_contract_gate.py tests/vertical/api/test_upstream_error_mapping.py tests/unit/test_api_auth_service.py tests/unit/test_core_services_async_contract.py tests/unit/test_legacy_core_services_adapter.py`
  - `uv run --extra test pytest -q`
- Risks / TBD:
  - Full-repository lint/typecheck debt outside the phase hotspot scope remains and is intentionally deferred.
  - Internal legacy alias symbols still exist in service runtime/composition/client exports and are scheduled for Phase 27 cleanup.
- Next recommended phase: Phase 27 Provider Runtime Containment / Async Migration.

---

## Phase 27: Provider Runtime Containment / Async Migration
### Goal
Finalize the service runtime direction and remove residual legacy coupling/aliases.

### Checklist
- [x] Choose and lock final provider runtime target:
  - [ ] Option A: async-native provider runtime for all domains.
  - [x] Option B: strict containment layer for legacy runtime behind stable async adapter boundary.
- [x] Remove internal legacy alias symbols that invite accidental reuse.
- [x] Ensure challenge-driven behavior works consistently across all service domains under final runtime.
- [x] Update migration/release documentation for runtime transition impact.
- [x] Execute full gate (`format`, `lint`, `typecheck`, `tests`) on final runtime path.

### Exit Criteria
- [x] Runtime direction is explicit, enforced, and documented.
- [x] No hidden dependency on legacy-named runtime symbols remains in active paths.

### Handoff: Phase 27 - Provider Runtime Containment / Async Migration
- Date: 2026-03-06
- Status: Done
- Summary:
  - Locked runtime strategy to Option B (strict containment) and enforced it with dedicated containment tests (`tests/unit/test_service_runtime_containment.py`).
  - Removed internal legacy alias symbols in runtime/composition (`LegacyServicesRuntime`, `LegacyServicesAdapterBase`, `LegacyCoreAdapterBundle`, `build_legacy_core_adapter_bundle`) and migrated all service adapters/clients to canonical runtime names.
  - Extended challenge-contract parity coverage to read and mutation endpoints across all service domains via `tests/integration/test_challenge_contract_gate.py`.
  - Updated release/migration documentation to reflect final runtime direction and alias removals (`ARCHITECTURE.md`, `README.md`, `CHANGELOG.md`).
- Files changed:
  - `pyicloud/adapters/services/{runtime.py,composition.py,legacy_core.py,account.py,calendar.py,contacts.py,devices.py,drive.py,photos.py,reminders.py,ubiquity.py,content.py}`
  - `pyicloud/adapters/services/clients/{account.py,calendar.py,contacts.py,devices.py,drive.py,photos.py,reminders.py,ubiquity.py}`
  - `tests/unit/test_legacy_alias_export_ratchet.py`
  - `tests/unit/test_service_runtime_containment.py`
  - `tests/integration/test_challenge_contract_gate.py`
  - `Makefile`
  - `.github/workflows/pythonlint.yml`
  - `ARCHITECTURE.md`
  - `README.md`
  - `CHANGELOG.md`
  - `docs/refactor_plan.md`
- Tests executed:
  - `uv run --extra test pytest --no-cov -q tests/unit/test_legacy_core_services_adapter.py tests/unit/test_core_services_async_contract.py tests/unit/test_legacy_alias_export_ratchet.py tests/unit/test_service_contract_dto_mappers.py`
  - `uv run --extra test pytest --no-cov -q tests/integration/test_challenge_contract_gate.py tests/unit/test_service_runtime_containment.py tests/unit/test_legacy_alias_export_ratchet.py tests/unit/test_legacy_core_services_adapter.py tests/unit/test_core_services_async_contract.py`
  - `uv run --extra lint ruff format pyicloud/api/errors.py pyicloud/application/api_auth.py pyicloud/application/core_services.py pyicloud/adapters/services/runtime.py tests/integration/test_challenge_contract_gate.py tests/unit/test_hexagonal_import_boundaries.py tests/unit/test_legacy_alias_export_ratchet.py tests/unit/test_service_runtime_containment.py --check`
  - `uv run --extra lint ruff check pyicloud/api/errors.py pyicloud/application/api_auth.py pyicloud/application/core_services.py pyicloud/adapters/services/runtime.py tests/integration/test_challenge_contract_gate.py tests/unit/test_hexagonal_import_boundaries.py tests/unit/test_legacy_alias_export_ratchet.py tests/unit/test_service_runtime_containment.py`
  - `uv run --extra lint mypy --follow-imports=skip pyicloud/application/api_auth.py pyicloud/application/core_services.py pyicloud/api/errors.py pyicloud/adapters/services/runtime.py`
  - `uv run --extra test pytest -q -o addopts='' --cov=pyicloud.application.api_auth --cov=pyicloud.api.errors --cov=pyicloud.adapters.services.runtime --cov=pyicloud.adapters.services --cov-report=term-missing --cov-fail-under=82 tests/integration/test_challenge_contract_gate.py tests/vertical/api/test_upstream_error_mapping.py tests/unit/test_api_auth_service.py tests/unit/test_core_services_async_contract.py tests/unit/test_legacy_core_services_adapter.py tests/unit/test_service_runtime_containment.py`
  - `uv run --extra test pytest -q`
- Risks / TBD:
  - None for this phase.
- Next recommended phase: Phase 28 Credential Custody Hardening.

---

## Phase 28-33 Program: Secure Auth, Access Control, Unified Challenge, and Operation Suspension
### Summary (locked)
- `password` custody in CLI only (encrypted at rest), never persisted by backend.
- Hybrid access-control model:
  - `dev/local`: relaxed onboarding for iteration speed.
  - `staging/prod`: strict allowlist + admin + durable stores mandatory.
- Single auth entrypoint `POST /v1/auth/challenge` with explicit challenge state machine.
- Server-side Operation Suspension Pattern for challenge-driven resume after Apple reauth/MFA.

### Public API / Interface Changes (locked)
- New endpoint:
  - `POST /v1/auth/challenge` (state-machine contract).
- New admin endpoints (JWT admin role required):
  - `GET /v1/admin/allowlist`
  - `POST /v1/admin/allowlist`
  - `DELETE /v1/admin/allowlist/{username}`
  - `POST /v1/admin/allowlist/{username}/role`
- Updated challenge details in protected-route errors:
  - include `challenge_id`, `challenge_type`, `session_id`, `operation_id`, `next_step`.
- JWT claims extension:
  - `role` and `acl_version` (for stale-admin invalidation).
- Keep `/v1/auth/login` and `/v1/auth/security-code` as temporary compatibility shims during migration window.

### Program Test Plan (locked)
- Unit:
  - challenge state-machine transitions and invalid-transition rejection.
  - backend serialization/store tests proving no password persistence.
  - allowlist/admin authorization matrix and bootstrap-admin path.
- Integration:
  - operation suspension for read/mutation routes with resume success/failure/timeout.
  - anti-replay, attempt-limit, and rate-limit behavior.
- Vertical CLI/API:
  - unified challenge flow including 2FA and resumed operation.
- Regression:
  - existing `auth_challenge_required` envelope remains backward-compatible during migration window.

### Risk Evaluation and Mitigation Strategy (locked)
- Custom crypto mistakes for `password_cyphered`:
  - Use standard sealed-box libs (libsodium/PyNaCl), versioned key IDs, key rotation support, no custom primitives.
- Replay/double-execution on suspended mutations:
  - Mandatory idempotency keys, one-time resume tokens, terminal operation states.
- Challenge hijack/cross-account completion:
  - Bind challenge to `username + session_id + client fingerprint`; single-use step tokens; short TTL.
- Allowlist misconfiguration/admin lockout:
  - Bootstrap-admin break-glass flow in non-dev; immutable audit log; explicit last-admin removal guard.
- DoS via unbounded pending challenges/operations:
  - Per-user/global quotas, TTL sweeper, payload caps, request rate limits.
- Multi-instance consistency gaps:
  - Durable shared stores required in `staging/prod`; memory backends only in `dev/local`.

### Assumptions and Defaults (locked)
- Keep `401` for `auth_challenge_required` to preserve existing client semantics.
- Backend never persists Apple password at rest.
- CLI is the only component allowed to store Apple password locally, and only encrypted at rest.

---

## Phase 28: Credential Custody Hardening
### Goal
Ensure backend handles Apple password only in memory, never at rest, while enabling secure CLI-side credential storage.

### Checklist
- [x] Remove backend password persistence from settings/session serialization paths.
- [x] Add explicit guard tests proving backend stores/files never persist plaintext password artifacts.
- [ ] Add CLI credential vault adapter:
  - [x] OS keyring backend first.
  - [x] encrypted-file fallback explicitly disabled by default.
- [x] Wire CLI auth commands/challenge middleware to consume credential vault where available.

### Exit Criteria
- Backend writes zero plaintext password artifacts in config/session/challenge stores.
- CLI can securely store/retrieve encrypted credential locally for challenge continuation.

### Handoff: Phase 28 - Credential Custody Hardening
- Date: 2026-03-06
- Status: Done
- Summary:
  - Enforced password-redaction at persistence boundary by hardening `SettingsFile.save()` to always exclude `account.password`.
  - Added backend guard tests verifying neither settings persistence nor legacy session update writes plaintext password to disk.
  - Added optional OS-keyring credential vault adapter for CLI and wired it into auth login + challenge completion flow without enabling file fallback.
- Files changed:
  - `pyicloud/paths.py`
  - `tests/unit/test_paths.py`
  - `tests/unit/test_session_adapter.py`
  - `pyicloud/cli/credential_vault.py`
  - `pyicloud/cli/commands/auth.py`
  - `pyicloud/cli/transport.py`
  - `pyicloud/cli/main.py`
  - `tests/unit/test_cli_credential_vault.py`
  - `tests/unit/test_cli_transport.py`
- Tests executed:
  - `uv run pytest -q -o addopts='' tests/unit/test_paths.py tests/unit/test_session_adapter.py`
  - `uv run pytest -q -o addopts='' tests/unit/test_cli_credential_vault.py tests/unit/test_cli_transport.py tests/vertical/cli/test_auth_cli.py`
- Risks / TBD:
  - Keyring remains optional (`import keyring` best-effort); non-keyring environments fall back to prompt-based password entry (no at-rest storage).
- Next recommended phase: Phase 29 Access Control Plane (Whitelist + Admin).

---

## Phase 29: Access Control Plane (Whitelist + Admin)
### Goal
Prevent arbitrary Apple accounts from using backend by enforcing admin-managed allowlist policies.

### Checklist
- [x] Introduce allowlist/admin domain model:
  - [x] fields include `username`, `roles`, `status`, `created_by`, timestamps.
- [x] Add persistence adapter for access-control state.
- [x] Enforce allowlist gate before auth flow starts.
- [x] Add bootstrap-admin mechanism for first setup in non-dev environments.
- [x] Add admin API for allowlist management:
  - [x] list/add/remove/promote/demote.
- [x] Add role-aware JWT claim issuance/validation (`role`, `acl_version`) and stale-ACL invalidation behavior.

### Exit Criteria
- Unauthorized Apple accounts are rejected with `403` before auth/challenge execution.
- Admin can manage allowlist lifecycle without direct file edits.

### Handoff: Phase 29 - Access Control Plane (Whitelist + Admin)
- Date: 2026-03-06
- Status: Done
- Summary:
  - Added a dedicated access-control domain model and ports with `memory`/`file` adapters for allowlist/admin state.
  - Enforced allowlist gates before auth execution in strict environments and added bootstrap-admin setup for non-dev runtime initialization.
  - Extended JWT ACL context with `role` and `acl_version`, including stale-ACL token invalidation in session validation.
  - Added admin management endpoints (`list/add/remove/role`) protected by admin-role authorization with last-admin guards.
- Files changed:
  - `pyicloud/domain/api_models.py`
  - `pyicloud/domain/api_errors.py`
  - `pyicloud/domain/__init__.py`
  - `pyicloud/ports/access_control.py`
  - `pyicloud/ports/__init__.py`
  - `pyicloud/adapters/access/__init__.py`
  - `pyicloud/adapters/access/in_memory_access_control.py`
  - `pyicloud/adapters/access/file_access_control.py`
  - `pyicloud/application/access_control.py`
  - `pyicloud/application/__init__.py`
  - `pyicloud/application/api_auth.py`
  - `pyicloud/bootstrap/api_runtime.py`
  - `pyicloud/bootstrap/__init__.py`
  - `pyicloud/api/app.py`
  - `pyicloud/api/dependencies.py`
  - `pyicloud/api/errors.py`
  - `pyicloud/api/routers/auth.py`
  - `pyicloud/api/routers/admin.py`
  - `pyicloud/api/routers/__init__.py`
  - `pyicloud/api/schemas/admin.py`
  - `pyicloud/api/schemas/__init__.py`
  - `tests/fakes/auth_scenarios.py`
  - `tests/unit/test_access_control_store.py`
  - `tests/unit/test_access_control_api_service.py`
  - `tests/unit/test_api_auth_access_control.py`
  - `tests/unit/test_api_app_auth_config.py`
  - `tests/vertical/api/test_admin_api.py`
- Tests executed:
  - `uv run pytest -q -o addopts='' tests/unit/test_access_control_store.py tests/unit/test_access_control_api_service.py tests/unit/test_api_app_auth_config.py`
  - `uv run pytest -q -o addopts='' tests/unit/test_api_auth_service.py tests/unit/test_api_auth_access_control.py tests/vertical/api/test_auth_api.py tests/integration/test_api_contracts.py`
  - `uv run pytest -q -o addopts='' tests/vertical/api/test_admin_api.py tests/vertical/api/test_auth_api.py tests/vertical/api/test_devices_api.py tests/integration/test_challenge_contract_gate.py`
  - `uv run pytest -q -o addopts='' tests/vertical/api`
  - `uv run pytest -q -o addopts='' tests/integration/test_api_contracts.py tests/integration/test_api_end_to_end.py tests/integration/test_challenge_contract_gate.py`
  - `uv run pytest -q -o addopts='' tests/unit/test_access_control_store.py tests/unit/test_access_control_api_service.py tests/unit/test_api_auth_access_control.py tests/unit/test_api_auth_service.py tests/unit/test_api_app_auth_config.py`
- Risks / TBD:
  - Default `memory` ACL backend remains acceptable only for dev/local; production-grade distributed consistency requirements stay deferred to upcoming phases.
  - Legacy `/v1/auth/login` and `/v1/auth/security-code` remain active and must be migrated to unified challenge endpoint in Phase 30.
- Next recommended phase: Phase 30 Unified Auth Challenge Endpoint.

---

## Phase 30: Unified Auth Challenge Endpoint
### Goal
Consolidate interactive authentication into one state-machine endpoint.

### Checklist
- [x] Introduce `POST /v1/auth/challenge` as the canonical interactive auth endpoint.
- [x] Support staged request inputs:
  - [x] `username`
  - [x] `challenge_id`
  - [x] `password_envelope`
  - [x] `security_code`
- [x] Standardize response contract:
  - [x] explicit `challenge_type` in `password_required | security_code_required | authenticated | operation_resume_required`.
  - [x] include `challenge_id`, `session_id`, `expires_at`, `retryable`.
- [x] Keep `/v1/auth/login` and `/v1/auth/security-code` as temporary compatibility shims forwarding internally to challenge service.
- [x] Add strict transition validation to reject invalid or replayed challenge steps.

### Exit Criteria
- Auth handshake is represented by one explicit server-side state machine and one public interactive entrypoint.
- Legacy auth endpoints remain operational only as compatibility wrappers.

### Handoff: Phase 30 - Unified Auth Challenge Endpoint
- Date: 2026-03-06
- Status: Done
- Summary:
  - Added unified interactive endpoint `POST /v1/auth/challenge` with staged request fields and explicit challenge state responses.
  - Implemented state-machine orchestration in `AuthApiService.challenge` for `password_required`, `security_code_required`, `authenticated`, and `operation_resume_required`.
  - Converted legacy `/v1/auth/login` and `/v1/auth/security-code` handlers into compatibility shims that forward internally to the challenge service.
  - Added strict transition checks and replay rejection semantics for invalid challenge step combinations and consumed challenge IDs.
- Files changed:
  - `pyicloud/domain/api_errors.py`
  - `pyicloud/domain/__init__.py`
  - `pyicloud/application/api_auth.py`
  - `pyicloud/api/schemas/auth.py`
  - `pyicloud/api/schemas/__init__.py`
  - `pyicloud/api/routers/auth.py`
  - `tests/unit/test_api_auth_challenge_state_machine.py`
  - `tests/vertical/api/test_auth_challenge_api.py`
- Tests executed:
  - `uv run pytest -q -o addopts='' tests/unit/test_api_auth_challenge_state_machine.py tests/unit/test_api_auth_service.py tests/vertical/api/test_auth_challenge_api.py tests/vertical/api/test_auth_api.py tests/integration/test_api_contracts.py tests/integration/test_api_end_to_end.py`
  - `uv run pytest -q -o addopts='' tests/integration/test_challenge_contract_gate.py tests/vertical/api/test_upstream_error_mapping.py`
- Risks / TBD:
  - `/v1/auth/challenge` currently expects plaintext `password_envelope` while cryptographic envelope transport remains pending for later hardening phases.
  - Operation suspension resume semantics are limited to challenge signaling; server-side suspended operation execution is deferred to Phase 31.
- Next recommended phase: Phase 31 Operation Suspension Pattern (Server-Side).

---
