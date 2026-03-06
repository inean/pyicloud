# Refactor Plan: Ports/Adapters + FastAPI + API-Driven CLI

## Resume Protocol (read this first)
1. Read this file fully.
2. Run baseline: `uv run --extra test pytest -q`.
3. Continue the first phase marked `In Progress`.
4. Do not start a new phase until this file is updated with completion evidence for the current one.

## Historical Archives
- `docs/refactor_plan_phases_1_10.md` (Phase 0-10, bootstrap + first wave).
- `docs/refactor_plan_phases_10_20.md` (Phase 10A-20).
- `docs/refactor_plan_phases_20_30.md` (Phase 21-30).

## Decision Snapshot (locked)
- First cycle scope: Auth + Account + Find My iPhone + Drive.
- CLI model: subcommands only.
- Compatibility policy: hard removal for legacy Python/library sync surfaces in this cycle.
- CLI transport: HTTP-first.
- API naming: domain-first.
- API versioning: `/v1`.
- Token format: JWT HS256 via PyJWT.
- Token persistence: file store + env override.
- Vertical tests: in-process ASGI only; no iCloud network calls.
- Legacy removal boundary: full removal of sync runtime and compatibility shims in this cycle.
- API/CLI domain continuity: keep current `/v1` routes and subcommands operational via async adapters.
- Public interface removals in this cycle (locked): `from pyicloud import PyiCloudService`, `pyicloud.services`, `pyicloud.legacy`, `pyicloud.cmdline`.
- Public interface continuity in this cycle (locked): existing `/v1/*` HTTP contracts and existing `pyicloud.cli.main` subcommands remain operational.
- Internal runtime lock: domain ports/adapters move to async-only runtime (no sync compatibility shims).
- Observability query scope: PromQL, TraceQL, and LogQL.
- Observability backend policy: project must run without observability dependencies via `null` adapters; `otel` adapter remains optional.
- Challenge-driven auth policy (locked): clients attempt normal domain operations first; when Apple session is expired/invalid, backend returns an auth challenge response and drives recovery (`client -> backend -> Apple`) instead of requiring preemptive login.
- Challenge persistence policy (locked): backend challenge state must never store plaintext credentials.

## Program 34+ Decision Addendum (locked)
- Taxonomía semántica por raíces: `contexts/core`, `contexts/services`, `contexts/crosscutting`.
- Contextos `services`: `devices`, `account`, `drive`, `calendar`, `contacts`, `reminders`, `photos`, `ubiquity`.
- Contextos `crosscutting`: `auth`, `telemetry`, `observability`.
- `identity_access` se renombra de forma definitiva a `auth`.
- `auth` se implementa como contexto transversal (`contexts/crosscutting/auth`), no en `core`.
- `API/CLI` salen de contextos de negocio y se ubican en `pyicloud/interfaces/api` y `pyicloud/interfaces/cli`.
- Regla de dependencias: strict inward (hacia dominio/puertos de contexto).
- Observabilidad separada en write/read: `crosscutting/telemetry` (emisión) y `crosscutting/observability` (consulta).
- Estrategia de migración: strangler por fases con shims internos temporales y retiro final obligatorio.

## Phase Board
- Planned:
  - None
- In Progress:
  - None
- Done:
  - Phase 31 Operation Suspension Pattern (Server-Side)
  - Phase 32 Abuse/Safety Hardening for New Flows
  - Phase 33 Migration, Compatibility, and Cutover
  - Phase 34 Semantic Taxonomy + Guardrails
  - Phase 35 Context Skeleton + Initial Moves
  - Phase 36 API/CLI Externalization to Interfaces
  - Phase 37 Crosscutting Auth Rewrite
  - Phase 38 Telemetry/Observability Split
  - Phase 39 Services Context Migration
  - Phase 40 Platform Extraction + Legacy Deletion
  - Phase 41 Shim Removal + Final Cutover
- Archived:
  - Phase 0-10: `docs/refactor_plan_phases_1_10.md`
  - Phase 10A-20: `docs/refactor_plan_phases_10_20.md`
  - Phase 21-30: `docs/refactor_plan_phases_20_30.md`
- Blocked:
  - None

## Closed Assumptions (locked)
- Prioritize functional continuity for `/v1/*` routes and `pyicloud.cli.main` subcommands during async migration; no intentional downtime window for domain routes.
- Preserve plan history/order and distribute async migration work inside existing phases/subphases.
- Operate on the current worktree without reverting unrelated changes.
- Unit and vertical suites run without external network; integration follows the repository policy.
- Client behavior assumption: no preflight session refresh; CLI/API clients call target operation first and only enter auth flow when backend returns challenge.
- Challenge completion is backend-mediated; clients never call Apple endpoints directly.
- La semántica de contexto prevalece sobre la estructura previa por capas globales.
- Los adapters de entrada (`api`, `cli`) son infraestructura de interfaz, no dominio.
- Los contextos `services` no invocan casos de uso de `observability`; emiten trazabilidad vía puerto técnico de `telemetry`.
- Se permiten breaking changes durante Programa 34+ cuando desbloquean la taxonomía semántica final.
- El protocolo de resume actual del documento se mantiene sin cambios.
- El Programa 34+ no reescribe el histórico de fases 0-33; añade una nueva ola de refactor semántico.
- `auth` queda definitivamente ubicado en `contexts/crosscutting/auth`.

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


## Phase 31: Operation Suspension Pattern (Server-Side)
### Goal
Pause protected operations while auth challenges complete, then resume server-side safely.

### Checklist
- [x] Add suspended-operation store with TTL and explicit states:
  - [x] `pending_auth`, `resuming`, `completed`, `failed`, `expired`.
- [x] On upstream reauth errors, return `401 auth_challenge_required` including `operation_id`.
- [x] On successful challenge completion, resume suspended operation in backend and return final operation result.
- [x] Enforce idempotency key requirement for mutating operations during suspend/resume.
- [x] Enforce terminal-state semantics to prevent duplicate resume execution.

### Exit Criteria
- Client no longer needs to manually replay original business operations after MFA.
- Mutating operations remain replay-safe under retries and partial failures.

### Handoff: Phase 31 - Operation Suspension Pattern (Server-Side)
- Date: 2026-03-06
- Status: Done
- Summary:
  - Added suspended-operation persistence model with explicit lifecycle states and TTL expiry behavior (`pending_auth`, `resuming`, `completed`, `failed`, `expired`).
  - Extended upstream challenge mapping to persist suspended operation context and include `operation_id` in `auth_challenge_required` responses.
  - Implemented server-side operation replay from `POST /v1/auth/challenge` after successful auth completion, returning replay status/payload in challenge response.
  - Enforced `Idempotency-Key` requirement for mutating operations when suspension is triggered and added terminal-state guards to avoid duplicate resume execution.
- Files changed:
  - `pyicloud/domain/api_models.py`
  - `pyicloud/domain/__init__.py`
  - `pyicloud/ports/operation_suspension.py`
  - `pyicloud/ports/__init__.py`
  - `pyicloud/adapters/operation_suspension/__init__.py`
  - `pyicloud/adapters/operation_suspension/in_memory_operation_store.py`
  - `pyicloud/adapters/operation_suspension/file_operation_store.py`
  - `pyicloud/application/operation_suspension.py`
  - `pyicloud/application/__init__.py`
  - `pyicloud/bootstrap/api_runtime.py`
  - `pyicloud/bootstrap/__init__.py`
  - `pyicloud/api/app.py`
  - `pyicloud/api/dependencies.py`
  - `pyicloud/api/errors.py`
  - `pyicloud/application/api_auth.py`
  - `pyicloud/api/routers/auth.py`
  - `pyicloud/api/schemas/auth.py`
  - `tests/unit/test_operation_suspension_store.py`
  - `tests/unit/test_operation_suspension_service.py`
  - `tests/unit/test_api_app_auth_config.py`
  - `tests/integration/test_challenge_contract_gate.py`
  - `tests/vertical/api/test_auth_challenge_api.py`
- Tests executed:
  - `uv run pytest -q -o addopts='' tests/unit/test_operation_suspension_store.py tests/unit/test_operation_suspension_service.py tests/unit/test_api_app_auth_config.py tests/integration/test_challenge_contract_gate.py tests/vertical/api/test_auth_challenge_api.py tests/vertical/api/test_upstream_error_mapping.py`
  - `uv run pytest -q -o addopts='' tests/unit/test_api_auth_challenge_state_machine.py tests/unit/test_api_auth_service.py tests/integration/test_api_contracts.py tests/integration/test_api_end_to_end.py tests/vertical/api`
- Risks / TBD:
  - Operation replay currently re-dispatches requests in-process and assumes JSON/text request bodies; broader content-type support requires follow-up hardening.
  - Distributed concurrency controls and replay-abuse quotas remain pending for Phase 32.
- Next recommended phase: Phase 32 Abuse/Safety Hardening for New Flows.

---

## Phase 32: Abuse/Safety Hardening for New Flows
### Goal
Bound abuse surface introduced by challenge and operation-suspension state.

### Checklist
- [x] Add challenge attempt limits, lockout windows, and rate limits per account/IP/session.
- [x] Add anti-replay controls:
  - [x] single-use challenge steps.
  - [x] nonce/session binding.
  - [x] strict transition graph enforcement.
- [x] Add quotas and payload caps for suspended operations:
  - [x] per user
  - [x] global
- [x] Add audit events:
  - [x] admin changes
  - [x] allowlist decisions
  - [x] challenge lifecycle
  - [x] operation resume outcomes
- [x] Add TTL sweepers and cleanup determinism tests for all new stores.

### Exit Criteria
- Auth/challenge/suspension paths have bounded resource usage, replay protections, and auditable security events.

### Handoff: Phase 32 - Abuse/Safety Hardening for New Flows
- Date: 2026-03-06
- Status: Done
- Summary:
  - Added auth abuse guard with per-account/IP/session attempt counters, lockout windows, and `429 auth_rate_limited` responses.
  - Hardened challenge transition checks with username/session binding and stricter invalid-transition rejection.
  - Added suspended-operation abuse controls: payload size caps plus per-user/global pending operation quotas.
  - Added structured audit events for admin allowlist mutations, allowlist deny decisions, challenge lifecycle, idempotency-key denials, and operation resume outcomes.
  - Added deterministic TTL/cleanup and guardrail tests covering new hardening controls.
- Files changed:
  - `pyicloud/application/auth_abuse_guard.py`
  - `pyicloud/application/api_auth.py`
  - `pyicloud/application/operation_suspension.py`
  - `pyicloud/application/__init__.py`
  - `pyicloud/api/app.py`
  - `pyicloud/api/dependencies.py`
  - `pyicloud/api/errors.py`
  - `pyicloud/api/routers/auth.py`
  - `pyicloud/api/routers/admin.py`
  - `pyicloud/api/schemas/auth.py`
  - `pyicloud/bootstrap/api_runtime.py`
  - `pyicloud/bootstrap/__init__.py`
  - `pyicloud/ports/operation_suspension.py`
  - `pyicloud/adapters/operation_suspension/in_memory_operation_store.py`
  - `pyicloud/adapters/operation_suspension/file_operation_store.py`
  - `tests/unit/test_auth_abuse_guard_service.py`
  - `tests/unit/test_api_auth_challenge_state_machine.py`
  - `tests/unit/test_operation_suspension_service.py`
  - `tests/unit/test_api_app_auth_config.py`
  - `tests/vertical/api/test_auth_challenge_api.py`
- Tests executed:
  - `uv run pytest -q -o addopts='' tests/unit/test_auth_abuse_guard_service.py tests/unit/test_operation_suspension_service.py tests/unit/test_operation_suspension_store.py tests/unit/test_api_auth_challenge_state_machine.py tests/unit/test_api_app_auth_config.py tests/integration/test_challenge_contract_gate.py tests/vertical/api/test_auth_challenge_api.py tests/vertical/api/test_auth_api.py tests/vertical/api/test_admin_api.py`
  - `uv run pytest -q -o addopts='' tests/unit/test_api_app_auth_config.py tests/integration/test_challenge_contract_gate.py tests/vertical/api/test_auth_api.py tests/vertical/api/test_admin_api.py tests/vertical/api/test_upstream_error_mapping.py tests/integration/test_api_contracts.py tests/integration/test_api_end_to_end.py`
  - `uv run pytest -q -o addopts='' tests/vertical/api`
- Risks / TBD:
  - Abuse guard counters are in-memory and instance-local; distributed rate-limit coordination remains a deployment concern.
  - Audit events are currently log-based; durable audit retention/queries are left for future observability hardening.
- Next recommended phase: Phase 33 Migration, Compatibility, and Cutover.

---

## Phase 33: Migration, Compatibility, and Cutover
### Goal
Migrate clients safely to unified challenge + suspension model and retire old auth endpoints.

### Checklist
- [x] Update CLI to use unified challenge endpoint and operation-resume semantics.
- [x] Roll out compatibility window for legacy auth endpoints.
- [x] Remove legacy `/v1/auth/login` and `/v1/auth/security-code` once cutover criteria are met.
- [x] Update docs/contracts/examples for new auth and admin surfaces.
- [x] Execute full gate (`format`, `lint`, `typecheck`, `tests`) on post-cutover path.

### Exit Criteria
- No active clients depend on legacy auth endpoints.
- Unified challenge + suspension path is the only supported authentication flow.

### Handoff: Phase 33 - Migration, Compatibility, and Cutover
- Date: 2026-03-06
- Status: Done
- Summary:
  - Migrated CLI auth and challenge middleware flows to `POST /v1/auth/challenge`.
  - Updated CLI auto-recovery to consume server-side `operation_result` and avoid redundant client-side replay when operation suspension resumes server-side.
  - Added automatic `Idempotency-Key` propagation for mutating CLI requests during challenge/retry handling.
- Files changed:
  - `pyicloud/cli/commands/auth.py`
  - `pyicloud/cli/transport.py`
  - `pyicloud/cli/main.py`
  - `pyicloud/api/routers/auth.py`
  - `pyicloud/api/schemas/auth.py`
  - `pyicloud/api/schemas/__init__.py`
  - `README.md`
  - `CODE_SAMPLES.md`
  - `tests/integration/test_api_contracts.py`
  - `tests/integration/test_api_end_to_end.py`
  - `tests/integration/test_challenge_contract_gate.py`
  - `tests/unit/test_api_auth_service.py`
  - `tests/unit/test_api_telemetry_middleware.py`
  - `tests/vertical/api/test_account_api.py`
  - `tests/vertical/api/test_admin_api.py`
  - `tests/vertical/api/test_auth_api.py`
  - `tests/vertical/api/test_auth_challenge_api.py`
  - `tests/vertical/api/test_calendar_api.py`
  - `tests/vertical/api/test_contacts_api.py`
  - `tests/vertical/api/test_devices_api.py`
  - `tests/vertical/api/test_drive_api.py`
  - `tests/vertical/api/test_observability_api.py`
  - `tests/vertical/api/test_photos_api.py`
  - `tests/vertical/api/test_reminders_api.py`
  - `tests/vertical/api/test_ubiquity_api.py`
  - `tests/vertical/api/test_upstream_error_mapping.py`
  - `pyicloud/application/api_auth.py`
  - `tests/unit/test_cli_transport.py`
  - `tests/vertical/cli/test_auth_cli.py`
- Tests executed:
  - `make check`
  - `uv run pytest -q -o addopts='' tests/unit/test_cli_transport.py tests/vertical/cli/test_auth_cli.py`
- Risks / TBD:
  - None identified in this phase after cutover and gate execution.
- Next recommended phase:
  - None (phase plan complete).

---

## Phase 34: Semantic Taxonomy + Guardrails
### Goal
Establecer taxonomía semántica obligatoria y guardrails de arquitectura para Programa 34+.

### Checklist
- [x] Crear tests de taxonomía de contextos (`core`, `services`, `crosscutting`).
- [x] Crear tests de matriz de imports/dependencias (strict inward).
- [x] Bloquear nuevos imports legacy mediante ratchets adicionales.
- [x] Definir convenciones de naming por contexto y validarlas en tests/guardrails.

### Exit Criteria
CI falla ante nuevas violaciones semánticas y el baseline queda verde.

### Handoff: Phase 34 - Semantic Taxonomy + Guardrails
- Date: 2026-03-06
- Status: Done
- Summary:
  - Added semantic guardrail tests for Program 34+ taxonomy roots and strict inward context import policy.
  - Added naming convention guardrails for context roots and locked services/crosscutting catalogs.
  - Added ratchet test to block reintroduction of removed legacy runtime import paths.
- Files changed:
  - `tests/unit/test_context_taxonomy_guardrails.py`
  - `tests/unit/test_legacy_import_ratchet.py`
  - `docs/refactor_plan.md`
- Tests executed:
  - `uv run --extra test pytest -q`
  - `uv run --extra test pytest -q -o addopts='' tests/unit/test_context_taxonomy_guardrails.py tests/unit/test_legacy_import_ratchet.py`
- Risks / TBD:
  - Strict inward and catalog checks are active only when `pyicloud/contexts/*` exists; Phase 35 introduces those packages.
- Next recommended phase:
  - Phase 35 Context Skeleton + Initial Moves.

---

## Phase 35: Context Skeleton + Initial Moves
### Goal
Crear estructura base de contextos y mover contratos iniciales con compatibilidad temporal.

### Checklist
- [x] Crear árboles `contexts/*`, `shared/kernel`, `platform`, `interfaces/*`.
- [x] Mover contratos de alto nivel de `domain/ports` a la nueva estructura de contextos.
- [x] Crear shims temporales para mantener runtime y tests durante la transición.

### Exit Criteria
La nueva estructura compila sin romper el runtime actual.

### Handoff: Phase 35 - Context Skeleton + Initial Moves
- Date: 2026-03-06
- Status: Done
- Summary:
  - Added semantic package roots for Program 34+ (`contexts`, `shared/kernel`, `platform`, `interfaces`).
  - Moved high-level port contracts from `pyicloud/ports/*` into context-scoped contract modules under `pyicloud/contexts/*/contracts/*`.
  - Replaced legacy `pyicloud/ports/*` modules with temporary compatibility shims that re-export canonical context contracts.
  - Added shim-conformance tests asserting old port imports and new context contracts resolve to identical symbols.
- Files changed:
  - `pyicloud/contexts/**/*`
  - `pyicloud/shared/**/*`
  - `pyicloud/platform/__init__.py`
  - `pyicloud/interfaces/**/*`
  - `pyicloud/ports/*.py`
  - `tests/unit/test_context_contract_shims.py`
  - `tests/unit/test_context_taxonomy_guardrails.py`
  - `docs/refactor_plan.md`
- Tests executed:
  - `uv run --extra test pytest -q -o addopts='' tests/unit/test_context_taxonomy_guardrails.py tests/unit/test_legacy_import_ratchet.py`
  - `uv run --extra test pytest -q -o addopts='' tests/unit/test_context_contract_shims.py tests/unit/test_context_taxonomy_guardrails.py tests/unit/test_legacy_import_ratchet.py`
  - `uv run --extra test pytest -q`
- Risks / TBD:
  - API/CLI runtime still lives under `pyicloud/api` and `pyicloud/cli`; relocation to `pyicloud/interfaces/*` is pending in Phase 36.
  - Port shims are transitional and must be retired in later cutover phases.
- Next recommended phase:
  - Phase 36 API/CLI Externalization to Interfaces.

---

## Phase 36: API/CLI Externalization to Interfaces
### Goal
Mover `api` y `cli` a infraestructura de entrada fuera de contextos de negocio.

### Checklist
- [x] Mover `pyicloud/api` y `pyicloud/cli` a `pyicloud/interfaces/api` y `pyicloud/interfaces/cli`.
- [x] Mantener routers/comandos agrupados por contexto semántico.
- [x] Adaptar composition root/bootstrap para resolver servicios desde la nueva ubicación.

### Exit Criteria
Los contratos API/CLI operan desde `interfaces/*` sin regresión funcional.

### Handoff: Phase 36 - API/CLI Externalization to Interfaces
- Date: 2026-03-06
- Status: Done
- Summary:
  - Relocated API and CLI runtime modules from `pyicloud/api` and `pyicloud/cli` into `pyicloud/interfaces/api` and `pyicloud/interfaces/cli`.
  - Kept routers and command groups intact under the new interface roots, preserving route and command behavior.
  - Added compatibility packages (`pyicloud.api`, `pyicloud.cli`) that alias canonical interface modules and submodules for transitional import continuity.
  - Updated project entrypoints and coverage configuration to target canonical `pyicloud.interfaces.*` modules.
  - Added compatibility tests validating old/new package forwarding behavior.
- Files changed:
  - `pyicloud/interfaces/api/**/*`
  - `pyicloud/interfaces/cli/**/*`
  - `pyicloud/api/__init__.py`
  - `pyicloud/cli/__init__.py`
  - `pyproject.toml`
  - `README.md`
  - `tests/unit/test_interfaces_externalization.py`
  - `docs/refactor_plan.md`
- Tests executed:
  - `uv run --extra test pytest -q -o addopts='' tests/unit/test_api_app_auth_config.py tests/unit/test_cli_transport.py tests/smoke/test_smoke.py`
  - `uv run --extra test pytest -q -o addopts='' tests/unit/test_interfaces_externalization.py tests/unit/test_api_app_auth_config.py tests/unit/test_cli_transport.py tests/smoke/test_smoke.py`
  - `uv run --extra test pytest -q -o addopts='' tests/vertical/cli/test_auth_cli.py::test_cli_auth_login_session_logout_flow tests/vertical/cli/test_account_cli.py::test_cli_account_commands tests/vertical/cli/test_observability_cli.py::test_cli_observability_flow_json tests/unit/test_interfaces_externalization.py`
  - `uv run --extra test pytest -q`
- Risks / TBD:
  - Compatibility aliases still preload submodules for monkeypatch/import stability; cleanup is deferred until final shim removal phase.
  - Remaining architectural relocation work continues in Phase 37+ for crosscutting auth and service contexts.
- Next recommended phase:
  - Phase 37 Crosscutting Auth Rewrite.

---

## Phase 37: Crosscutting Auth Rewrite
### Goal
Completar la migración de autenticación al contexto transversal `auth`.

### Checklist
- [x] Renombrar semánticamente `identity_access` a `auth` en estructuras y referencias.
- [x] Implementar flujo auth/challenge/session/token/ACL dentro de `contexts/crosscutting/auth`.
- [x] Retirar dependencias nucleares en `sessions/trees` del path activo de autenticación.

### Exit Criteria
Auth funciona completamente sobre el nuevo contexto transversal.

### Handoff: Phase 37 - Crosscutting Auth Rewrite
- Date: 2026-03-06
- Status: Done
- Summary:
  - Added ratchet tests to prevent semantic regressions from `auth` back to `identity_access`.
  - Migrated auth application services (`auth/challenge/session/token/ACL` orchestration) into `pyicloud/contexts/crosscutting/auth/application`.
  - Rewired active API runtime imports (`bootstrap` + `interfaces/api`) to use canonical auth-context application services.
  - Added compatibility shims under `pyicloud/application/*` and migration tests to guarantee old imports still resolve.
  - Replaced default active auth runtime backend in `build_default_auth_api_service` with context-local scenario adapter composition (no `trees/sessions` dependency); tree backend remains optional via explicit `PYICLOUD_API_AUTH_BACKEND=legacy_tree`.
  - Removed eager `pyicloud.bootstrap.auth_session` import from `pyicloud.bootstrap` via lazy shim export to prevent active API path from importing `trees/sessions`.
  - Added guardrail checks that active auth API path modules do not directly import `pyicloud.trees` or `pyicloud.sessions`.
- Files changed:
  - `pyicloud/contexts/crosscutting/auth/application/*`
  - `pyicloud/application/{api_auth,auth_session,access_control,auth_abuse_guard,operation_suspension,service_endpoint_restore}.py`
  - `pyicloud/bootstrap/{api_runtime.py,__init__.py}`
  - `pyicloud/interfaces/api/{app.py,dependencies.py,routers/auth.py,routers/admin.py}`
  - `tests/unit/test_auth_context_naming_ratchet.py`
  - `tests/unit/{test_auth_application_context_migration.py,test_api_app_auth_config.py}`
  - `docs/refactor_plan.md`
- Tests executed:
  - `uv run --extra test pytest -q -o addopts='' tests/unit/test_auth_context_naming_ratchet.py tests/unit/test_context_taxonomy_guardrails.py`
  - `uv run --extra test pytest -q -o addopts='' tests/unit/test_auth_application_context_migration.py tests/unit/test_api_auth_service.py tests/unit/test_access_control_api_service.py tests/unit/test_auth_abuse_guard_service.py tests/unit/test_operation_suspension_service.py tests/vertical/api/test_auth_challenge_api.py`
  - `uv run --extra test pytest -q -o addopts='' tests/unit/test_api_app_auth_config.py tests/vertical/api/test_auth_api.py tests/vertical/cli/test_auth_cli.py`
  - `uv run --extra test pytest -q -o addopts='' tests/unit/test_api_app_auth_config.py tests/unit/test_setup_tree_srp.py::test_account_login_without_trust_token_does_not_fail_early tests/unit/test_auth_application_context_migration.py`
  - `uv run --extra test pytest -q`
- Risks / TBD:
  - Optional legacy tree backend (`PYICLOUD_API_AUTH_BACKEND=legacy_tree`) remains available for controlled fallback and is intentionally outside the default active API auth path.
- Next recommended phase:
  - Phase 38 Telemetry/Observability Split.

---

## Phase 38: Telemetry/Observability Split
### Goal
Separar emisión de trazas y consulta observability en contextos transversales distintos.

### Checklist
- [x] Extraer write-side de trazabilidad a `contexts/crosscutting/telemetry`.
- [x] Mantener query-side en `contexts/crosscutting/observability`.
- [x] Instrumentar adapters outbound para emitir señales vía puerto técnico de telemetry.

### Exit Criteria
La trazabilidad end-to-end funciona sin acoplar servicios a la API de consulta observability.

### Handoff: Phase 38 - Telemetry/Observability Split
- Date: 2026-03-06
- Status: Done
- Summary:
  - Migrated active observability query application and adapter wiring to canonical context modules under `pyicloud/contexts/crosscutting/observability/*`.
  - Migrated telemetry write-side upstream probe runtime/adapters to canonical context modules under `pyicloud/contexts/crosscutting/telemetry/adapters/upstream_probe/*`.
  - Left legacy module paths (`pyicloud/application/observability.py`, `pyicloud/adapters/observability/*`, `pyicloud/adapters/upstream_probe/*`) as compatibility shims.
  - Rewired active API and transport paths to the context modules (`bootstrap`, `interfaces/api`, `service_http`, `upstream/runtime`).
  - Added telemetry-probe instrumentation to outbound observability backend calls in `OTelObservabilityAdapter` via `UpstreamTrafficProbePort`.
  - Added migration and adapter instrumentation tests for compatibility and active-path guardrails.
- Files changed:
  - `pyicloud/contexts/crosscutting/observability/application/*`
  - `pyicloud/contexts/crosscutting/observability/adapters/*`
  - `pyicloud/contexts/crosscutting/telemetry/adapters/upstream_probe/*`
  - `pyicloud/application/observability.py`
  - `pyicloud/adapters/observability/*`
  - `pyicloud/adapters/upstream_probe/*`
  - `pyicloud/bootstrap/api_runtime.py`
  - `pyicloud/interfaces/api/{app.py,dependencies.py,routers/observability.py}`
  - `pyicloud/adapters/session/service_http.py`
  - `pyicloud/upstream/runtime.py`
  - `tests/unit/{test_observability_context_migration.py,test_observability_otel_adapter.py}`
- Tests executed:
  - `uv run --extra test pytest -q -o addopts='' tests/unit/test_observability_application.py tests/unit/test_observability_context_migration.py tests/vertical/api/test_observability_api.py`
  - `uv run --extra test pytest -q -o addopts='' tests/unit/test_upstream_probe_runtime.py tests/unit/test_observability_context_migration.py tests/integration/test_upstream_probe_otel.py`
  - `uv run --extra test pytest -q -o addopts='' tests/unit/test_observability_null_adapter.py tests/unit/test_observability_otel_adapter.py tests/unit/test_observability_application.py tests/unit/test_observability_context_migration.py tests/vertical/api/test_observability_api.py tests/vertical/cli/test_observability_cli.py tests/integration/test_observability_otel_adapter.py tests/unit/test_upstream_probe_runtime.py tests/integration/test_upstream_probe_otel.py`
  - `uv run --extra test pytest -q -o addopts='' tests/integration/test_upstream_flow_sequence.py tests/unit/test_observability_context_migration.py`
  - `uv run --extra test pytest -q`
- Risks / TBD:
  - Legacy compatibility shims for observability and upstream probe remain intentionally active and are scheduled for removal in later cutover phases.
- Next recommended phase:
  - Phase 39 Services Context Migration.

---

## Phase 39: Services Context Migration
### Goal
Reubicar servicios de negocio por bounded context y descomponer fachadas monolíticas.

### Checklist
- [x] Mover adapters y casos de uso de dominios de servicio a `contexts/services/*`.
- [x] Descomponer `CoreServicesApi` monolítico en servicios de aplicación por contexto.

### Exit Criteria
Cada servicio queda aislado por bounded context con dependencias semánticas explícitas.

### Handoff: Phase 39 - Services Context Migration
- Date: 2026-03-06
- Status: Done
- Summary:
  - Created context-scoped application services for `devices`, `account`, `drive`, `calendar`, `contacts`, `reminders`, `photos`, and `ubiquity` under `pyicloud/contexts/services/*/application`.
  - Refactored `pyicloud/application/core_services.py` into a compatibility facade that delegates to those context services while keeping existing API router contract stable.
  - Added canonical context adapters under `pyicloud/contexts/services/*/adapters` and rewired active composition (`pyicloud/adapters/services/composition.py`) to use them.
  - Converted legacy service adapter modules in `pyicloud/adapters/services/*` into compatibility shims that re-export context adapter classes.
  - Added migration tests asserting both facade and adapter composition now resolve to context-scoped implementations.
- Files changed:
  - `pyicloud/contexts/services/*/application/*`
  - `pyicloud/contexts/services/*/adapters/*`
  - `pyicloud/application/core_services.py`
  - `pyicloud/adapters/services/{__init__.py,composition.py,account.py,calendar.py,contacts.py,devices.py,drive.py,photos.py,reminders.py,ubiquity.py}`
  - `tests/unit/test_services_application_context_migration.py`
- Tests executed:
  - `uv run --extra test pytest -q -o addopts='' tests/unit/test_core_services_async_contract.py tests/vertical/api/test_devices_api.py tests/vertical/api/test_account_api.py tests/vertical/api/test_drive_api.py tests/vertical/api/test_calendar_api.py tests/vertical/api/test_contacts_api.py tests/vertical/api/test_reminders_api.py tests/vertical/api/test_photos_api.py tests/vertical/api/test_ubiquity_api.py`
  - `uv run --extra test pytest -q -o addopts='' tests/unit/test_services_application_context_migration.py tests/unit/test_core_services_async_contract.py`
  - `uv run --extra test pytest -q -o addopts='' tests/unit/test_services_application_context_migration.py tests/unit/test_core_services_async_contract.py tests/unit/test_legacy_core_services_adapter.py tests/vertical/api/test_devices_api.py tests/vertical/api/test_account_api.py tests/vertical/api/test_drive_api.py tests/vertical/api/test_calendar_api.py tests/vertical/api/test_contacts_api.py tests/vertical/api/test_reminders_api.py tests/vertical/api/test_photos_api.py tests/vertical/api/test_ubiquity_api.py`
  - `uv run --extra test pytest -q`
- Risks / TBD:
  - Shared runtime/clients/mappers are still hosted in `pyicloud/adapters/services/*` and are candidates for extraction into `platform` in Phase 40.
- Next recommended phase:
  - Phase 40 Platform Extraction + Legacy Deletion.

---

## Phase 40: Platform Extraction + Legacy Deletion
### Goal
Extraer infraestructura técnica transversal y eliminar rutas legacy activas.

### Checklist
- [x] Mover runtime de proveedor, storage y telemetry infra a `platform`.
- [x] Eliminar `sessions/trees` y rutas legacy equivalentes del path activo.

### Exit Criteria
Cero rutas de ejecución activas hacia paquetes legacy retirados.

### Handoff: Phase 40 - Platform Extraction + Legacy Deletion
- Date: 2026-03-06
- Status: Done
- Summary:
  - Extracted upstream telemetry infrastructure from `pyicloud/upstream/*` into `pyicloud/platform/telemetry/upstream/*`.
  - Converted `pyicloud/upstream/*` modules into compatibility shims that re-export platform implementations.
  - Extracted provider runtime and session storage infrastructure into `pyicloud/platform/provider/runtime.py` and `pyicloud/platform/storage/session_store.py`.
  - Converted `pyicloud/adapters/services/runtime.py` and `pyicloud/adapters/store/file_session_store.py` into compatibility modules backed by platform implementations.
  - Rewired active composition/bootstrap imports to consume platform provider/storage modules where safe.
  - Removed the `legacy_tree` API auth backend route from `build_default_auth_api_service`, leaving challenge-driven auth backends as the active path.
  - Deferred `pyicloud.sessions` imports inside legacy provider refresh helpers so importing active service runtime paths no longer eagerly loads legacy sessions modules.
  - Added migration tests asserting shim identity and active transport path resolution against platform modules.
- Files changed:
  - `pyicloud/platform/telemetry/*`
  - `pyicloud/platform/telemetry/upstream/*`
  - `pyicloud/platform/provider/*`
  - `pyicloud/platform/storage/*`
  - `pyicloud/upstream/*`
  - `pyicloud/adapters/services/runtime.py`
  - `pyicloud/adapters/store/{__init__.py,file_session_store.py}`
  - `pyicloud/bootstrap/{api_runtime.py,auth_session.py,session_endpoint_restore.py}`
  - `pyicloud/adapters/auth/session_endpoint_restore.py`
  - `pyicloud/adapters/services/{__init__.py,composition.py,legacy_core.py,content.py,clients/*}`
  - `pyicloud/contexts/services/*/adapters/service.py`
  - `tests/unit/test_platform_upstream_migration.py`
  - `tests/unit/test_platform_runtime_storage_migration.py`
- Tests executed:
  - `uv run --extra test pytest -q -o addopts='' tests/unit/test_platform_upstream_migration.py tests/unit/test_upstream_probe_classification.py tests/unit/test_upstream_probe_sanitize.py tests/unit/test_upstream_probe_context.py tests/unit/test_upstream_probe_runtime.py tests/integration/test_upstream_flow_sequence.py`
  - `uv run --extra test pytest -q -o addopts='' tests/unit/test_platform_runtime_storage_migration.py tests/unit/test_file_session_store_adapter.py tests/unit/test_service_runtime_containment.py tests/unit/test_legacy_core_services_adapter.py tests/unit/test_platform_upstream_migration.py`
  - `uv run --extra test pytest -q -o addopts='' tests/unit/test_platform_runtime_storage_migration.py tests/unit/test_legacy_core_services_adapter.py tests/unit/test_service_runtime_containment.py tests/unit/test_file_session_store_adapter.py tests/unit/test_auth_bootstrap.py tests/unit/test_api_app_auth_config.py`
  - `uv run --extra test pytest -q`
- Risks / TBD:
  - Legacy package paths remain intentionally as compatibility shims and still need final cleanup/removal in Phase 41.
- Next recommended phase:
  - Phase 41 Shim Removal + Final Cutover.

---

## Phase 41: Shim Removal + Final Cutover
### Goal
Cerrar Programa 34+ eliminando compatibilidad temporal y consolidando documentación final.

### Checklist
- [x] Eliminar shims internos temporales de migración.
- [x] Endurecer ratchets/guardrails para impedir regresión estructural.
- [x] Actualizar `ARCHITECTURE.md`, `README.md`, `CODE_SAMPLES.md`.

### Exit Criteria
Estructura final estable, guardrails estrictos y documentación totalmente alineada.

### Handoff: Phase 41 - Shim Removal + Final Cutover
- Date: 2026-03-06
- Status: Done
- Summary:
  - Removed legacy upstream telemetry shim package (`pyicloud/upstream/*`) and rewired runtime imports/tests to canonical `pyicloud.platform.telemetry.upstream`.
  - Removed legacy `pyicloud.adapters.store` shim and moved remaining in-repo references to `pyicloud.platform.storage`.
  - Removed legacy `pyicloud.adapters.services.runtime` shim and rewired adapter composition/content/core facade and tests to canonical `pyicloud.platform.provider.runtime`.
  - Removed compatibility modules under `pyicloud/application/*` (except `core_services`) and rewired auth/observability imports/tests to canonical `pyicloud.contexts.crosscutting.*.application` modules.
  - Hardened legacy import ratchets to forbid reintroducing removed shim namespaces (`pyicloud.upstream`, `pyicloud.adapters.store`, `pyicloud.adapters.services.runtime`).
- Files changed:
  - `pyicloud/upstream/*` (deleted)
  - `pyicloud/adapters/store/*` (deleted)
  - `pyicloud/adapters/services/{__init__.py,composition.py,content.py,legacy_core.py,runtime.py}` (runtime shim deleted)
  - `pyicloud/sessions/{__init__.py,_transport.py}`
  - `pyicloud/adapters/session/service_http.py`
  - `pyicloud/contexts/services/*/application/service.py`
  - `pyicloud/contexts/crosscutting/{auth/application/auth_session.py,observability/adapters/otel.py}`
  - `tests/unit/{test_platform_upstream_migration.py,test_upstream_probe_classification.py,test_upstream_probe_context.py,test_upstream_probe_sanitize.py,test_file_session_store_adapter.py,test_platform_runtime_storage_migration.py,test_service_runtime_containment.py,test_legacy_core_services_adapter.py,test_legacy_import_ratchet.py}`
  - `tests/integration/test_upstream_flow_sequence.py`
  - `tests/fakes/auth_scenarios.py`
  - `pyicloud/application/{__init__.py,access_control.py,api_auth.py,auth_abuse_guard.py,auth_session.py,observability.py,operation_suspension.py,service_endpoint_restore.py}`
  - `pyicloud/bootstrap/{auth_session.py,session_endpoint_restore.py}`
  - `pyicloud/cli_auth.py`
  - `tests/unit/test_removed_shim_files_ratchet.py`
  - `ARCHITECTURE.md`
  - `README.md`
  - `CODE_SAMPLES.md`
- Tests executed:
  - `uv run --extra test pytest -q -o addopts='' tests/unit/test_platform_upstream_migration.py tests/unit/test_upstream_probe_classification.py tests/unit/test_upstream_probe_context.py tests/unit/test_upstream_probe_sanitize.py tests/unit/test_legacy_import_ratchet.py tests/unit/test_session_base_transport.py tests/integration/test_upstream_flow_sequence.py`
  - `uv run --extra test pytest -q -o addopts='' tests/unit/test_file_session_store_adapter.py tests/unit/test_platform_runtime_storage_migration.py tests/unit/test_legacy_import_ratchet.py tests/vertical/api/test_auth_api.py`
  - `uv run --extra test pytest -q -o addopts='' tests/unit/test_service_runtime_containment.py tests/unit/test_platform_runtime_storage_migration.py tests/unit/test_legacy_core_services_adapter.py tests/unit/test_legacy_import_ratchet.py tests/unit/test_file_session_store_adapter.py tests/unit/test_api_app_auth_config.py`
  - `uv run --extra test pytest -q -o addopts='' tests/unit/test_access_control_api_service.py tests/unit/test_api_auth_access_control.py tests/unit/test_api_auth_challenge_state_machine.py tests/unit/test_api_auth_service.py tests/unit/test_auth_abuse_guard_service.py tests/unit/test_auth_application_context_migration.py tests/unit/test_auth_session_flow.py tests/unit/test_auth_session_store_integration.py tests/unit/test_legacy_import_ratchet.py tests/unit/test_observability_application.py tests/unit/test_observability_context_migration.py tests/unit/test_operation_suspension_service.py tests/unit/test_service_endpoint_restore.py tests/unit/test_removed_shim_files_ratchet.py tests/integration/test_auth_tree_srp_flow.py tests/integration/test_observability_otel_adapter.py tests/integration/test_upstream_flow_sequence.py tests/vertical/api/test_admin_api.py tests/vertical/api/test_auth_challenge_api.py`
  - `uv run --extra test pytest -q -o addopts='' tests/unit/test_removed_shim_files_ratchet.py tests/unit/test_legacy_import_ratchet.py tests/unit/test_platform_upstream_migration.py tests/unit/test_platform_runtime_storage_migration.py`
  - `uv run --extra test pytest -q`
- Risks / TBD:
  - `pyicloud.ports/*` facades are intentionally retained as stable boundary aliases over canonical context contracts.
- Next recommended phase:
  - Program 34+ complete (no pending refactor phase on board).

## Next Session Start Here
```bash
cd /Users/inean/Projects/Legacy/Sandbox/pyicloud
uv run --extra test pytest -q
# Program 34+ phase board complete.
# Start from maintenance/new feature work on top of `dev`.
```
