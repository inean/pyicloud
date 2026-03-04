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

## Phase Board
- Planned:
  - Phase 8 Secondary Services I
  - Phase 9 Secondary Services II
  - Phase 10 Legacy Cleanup + Hardening
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
- [ ] Add Calendar, Contacts, Reminders ports/adapters/routes/CLI.
- [ ] Add deterministic vertical tests.

### Exit Criteria
All three domains reachable and tested via API/CLI.

---

## Phase 9: Secondary Services II
### Checklist
- [ ] Add Photos + Ubiquity ports/adapters/routes/CLI.
- [ ] Add deterministic vertical tests.

### Exit Criteria
Remaining library service functionality exposed through API/CLI.

---

## Phase 10: Legacy Cleanup + Hardening
### Checklist
- [ ] Remove legacy modules no longer needed:
  - [ ] `pyicloud/adapters/auth/legacy_cli_auth.py`
  - [ ] `pyicloud/services/endpoint_adapter.py`
  - [ ] `pyicloud/services/session_adapter.py`
- [ ] Remove dead compatibility branches while preserving supported facade.
- [ ] Update docs/contributing architecture references.
- [ ] Run full suite and vertical suite green.

### Exit Criteria
Core legacy auth/session coupling removed, docs aligned, test suites green.

## Next Session Start Here
```bash
cd /Users/inean/Projects/Legacy/Sandbox/pyicloud
uv run --extra test pytest -q
# Continue Phase 8 from docs/refactor_plan.md
```
