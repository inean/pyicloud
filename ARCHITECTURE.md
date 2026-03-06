# Architecture

## Objetivo

`pyicloud` sigue una arquitectura hexagonal orientada a dos superficies publicas:

- API HTTP (`/v1/*`) con FastAPI.
- CLI de subcomandos (`icloud ...`) que consume la API.

La libreria ya no expone superficies legacy sincronas para uso publico.

## Principios

- API-first y CLI-first.
- Dependencias dirigidas hacia el dominio (puertos en `pyicloud/ports`).
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
- `pyicloud/application/core_services.py`
- `pyicloud/contexts/crosscutting/observability/application/observability.py`

Responsabilidad: orquestar casos de uso de autenticacion, dominios core y observabilidad.

### 3) Domain contracts (ports)

- `pyicloud/ports/auth.py`
- `pyicloud/ports/services.py`
- `pyicloud/ports/session.py`
- `pyicloud/ports/observability.py`
- `pyicloud/ports/upstream_probe.py`

Responsabilidad: definir interfaces estables para separar dominio e infraestructura.

### 4) Infrastructure adapters

- `pyicloud/adapters/auth/*`
- `pyicloud/adapters/session/*`
- `pyicloud/adapters/store/*`
- `pyicloud/adapters/services/*`
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
- `pyicloud/application/`: shims de compatibilidad + casos de uso heredados en migracion.
- `pyicloud/ports/`: contratos hexagonales.
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
- Nuevas capacidades deben entrar por:
  1. Puerto en `pyicloud/ports`.
  2. Implementacion en `pyicloud/adapters`.
  3. Orquestacion en `pyicloud/application`.
  4. Exposicion en API/CLI.
  5. Tests unit + integration + vertical.
