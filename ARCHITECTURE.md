# Architecture

## Objetivo

`pyicloud` sigue una arquitectura hexagonal orientada a dos superficies publicas:

- API HTTP (`/v1/*`) con FastAPI.
- CLI de subcomandos (`icloud ...`) que consume la API.

La libreria ya no expone superficies legacy sincronas para uso publico.

## Principios

- API-first y CLI-first.
- Dependencias dirigidas hacia el dominio (contratos canonicos en `pyicloud/contexts/*/contracts`).
- Adaptadores de infraestructura en `pyicloud/adapters`.
- Runtime de proveedor bloqueado en **Option B (strict containment)**:
  - clientes legacy sincronos encapsulados detras de frontera async estable.
  - operaciones bloqueantes aisladas en `ServicesAdapterBase._run_blocking` (thread offload).
- Contratos HTTP estables con envelope:
  - exito: `{"data": ...}`
  - error: `{"error": {"code", "message", "status", "details"}}`
- Tests deterministas sin red externa por defecto.

## Capas

### 1) Interface layer

- `pyicloud/interfaces/api/app.py`: rutas FastAPI `/v1/*`.
- `pyicloud/interfaces/cli/main.py`: comandos `icloud`.

Responsabilidad: validar I/O, mapear errores y llamar casos de uso.

### 2) Application layer

- `pyicloud/contexts/crosscutting/auth/application/api_auth.py`
- `pyicloud/contexts/services/*/application/service.py`
- `pyicloud/application/core_services.py` (facade de compatibilidad)
- `pyicloud/contexts/crosscutting/observability/application/observability.py`

Responsabilidad: orquestar casos de uso de autenticacion, servicios de dominio y observabilidad.

### 3) Domain contracts (ports)

- `pyicloud/contexts/crosscutting/auth/contracts/*`
- `pyicloud/contexts/services/contracts/services.py`
- `pyicloud/contexts/crosscutting/observability/contracts/observability.py`
- `pyicloud/contexts/crosscutting/telemetry/contracts/upstream_probe.py`

Responsabilidad: definir interfaces estables para separar dominio e infraestructura.
Nota: `pyicloud/ports/*` se mantiene como fachada de compatibilidad.

### 4) Infrastructure adapters

- `pyicloud/adapters/auth/*`
- `pyicloud/adapters/session/*`
- `pyicloud/contexts/services/*/adapters/*`
- `pyicloud/platform/provider/runtime.py`
- `pyicloud/platform/storage/session_store.py`
- `pyicloud/platform/telemetry/upstream/*`
- `pyicloud/adapters/services/*` (clientes/mappers + facades acotadas)
- `pyicloud/contexts/crosscutting/observability/adapters/*`
- `pyicloud/contexts/crosscutting/telemetry/adapters/upstream_probe/*`

Responsabilidad: implementar puertos (HTTP cliente, almacenamiento de sesion, telemetria, etc.).

## Flujos principales

### Auth flow

1. CLI/API recibe credenciales.
2. `ApiAuthService` ejecuta login/security-code/session/logout.
3. Adaptadores de auth/session persisten estado y token.
4. Respuesta vuelve como envelope HTTP y salida CLI.

### Domain flow (devices/account/drive/... )

1. CLI llama endpoint `/v1/<dominio>`.
2. Handler FastAPI invoca `CoreServicesApi` (async).
3. `CoreServicesApi` coordina puertos de servicios.
4. Adaptadores de servicios ejecutan llamadas proveedor y mapean payloads.

## Estructura del codigo (resumen)

- `pyicloud/interfaces/api/`: capa HTTP.
- `pyicloud/interfaces/cli/`: capa CLI.
- `pyicloud/contexts/crosscutting/*/application`: casos de uso transversales.
- `pyicloud/contexts/services/*/{application,adapters}`: casos de uso y adapters por bounded context.
- `pyicloud/platform/{provider,storage,telemetry}`: infraestructura tecnica transversal.
- `pyicloud/application/`: shims de compatibilidad + casos de uso heredados en migracion.
- `pyicloud/ports/`: fachadas de compatibilidad para contratos.
- `pyicloud/adapters/`: infraestructura.
- `pyicloud/domain/`: modelos/errores de dominio.
- `pyicloud/sessions/`, `pyicloud/trees/`: flujos de sesion y auth.
- `tests/unit|integration|vertical|smoke`: matriz de pruebas.

## Observabilidad

- Consultas: PromQL, TraceQL y LogQL via API/CLI.
- Instrumentacion de rutas disponible en `pyicloud/interfaces/api/instrumentation.py`.
- Query-side en `pyicloud/contexts/crosscutting/observability/*`.
- Write-side de trazabilidad en `pyicloud/contexts/crosscutting/telemetry/adapters/upstream_probe/*`.
- La aplicacion debe funcionar sin dependencias de observabilidad (adaptadores `null`).

## Reglas de evolucion

- No reintroducir superficies retiradas:
  - `from pyicloud import PyiCloudService`
  - `pyicloud.services`
  - `pyicloud.legacy`
  - `pyicloud.cmdline`
- No reintroducir aliases legacy internos retirados del runtime/composicion:
  - `LegacyServicesRuntime`
  - `LegacyServicesAdapterBase`
  - `LegacyCoreAdapterBundle`
  - `build_legacy_core_adapter_bundle`
- No reintroducir namespaces shim eliminados:
  - `pyicloud.upstream`
  - `pyicloud.adapters.store`
  - `pyicloud.adapters.services.runtime`
- Nuevas capacidades deben entrar por:
  1. Contrato en `pyicloud/contexts/*/contracts`.
  2. Implementacion en `pyicloud/adapters` o `pyicloud/platform`.
  3. Orquestacion en `pyicloud/contexts/*/application` (o facade cuando aplique).
  4. Exposicion en API/CLI.
  5. Tests unit + integration + vertical.
