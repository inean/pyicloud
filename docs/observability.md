# Observability Query API (PromQL / TraceQL / LogQL)

The project exposes observability query endpoints through a hexagonal port so the
application core does not depend directly on OpenTelemetry SDK packages.

## Adapter modes

- `null` (default): deterministic no-backend responses, no optional dependencies.
- `otel`: backend HTTP execution with optional OTel span emission around query calls.

Configure mode with:

```bash
export PYICLOUD_OBSERVABILITY_ADAPTER=null  # default
```

or:

```bash
export PYICLOUD_OBSERVABILITY_ADAPTER=otel
export PYICLOUD_OBSERVABILITY_PROMQL_ENDPOINT="https://prometheus.example/api/v1/query"
export PYICLOUD_OBSERVABILITY_TRACEQL_ENDPOINT="https://tempo.example/api/search"
export PYICLOUD_OBSERVABILITY_LOGQL_ENDPOINT="https://loki.example/loki/api/v1/query"
export PYICLOUD_OBSERVABILITY_TIMEOUT_SECONDS=10
```

When `PYICLOUD_OBSERVABILITY_ADAPTER=otel`, optional dependencies are required:

```bash
uv sync --extra otel
```

## Upstream MITM capture (Phase 20A)

The project now supports internal MITM-style capture for all outbound traffic from
pyicloud to Apple endpoints (auth + legacy service calls), without external proxy tooling.

### Runtime controls

```bash
export PYICLOUD_UPSTREAM_CAPTURE_ENABLED=true
export PYICLOUD_UPSTREAM_PROBE_ADAPTER=otel
export PYICLOUD_UPSTREAM_ALLOWED_ENVS=dev,qa
export PYICLOUD_UPSTREAM_CAPTURE_BODY_MAX_BYTES=16384
```

Guardrail behavior:

- capture is disabled by default.
- if capture is enabled outside allowed environments, startup fails fast.
- sensitive values are always redacted (cookies/tokens/password/session identifiers).

### Correlation model

Each request event is tagged with:

- `pyicloud.flow_id`
- `pyicloud.operation`
- `pyicloud.step`
- `pyicloud.account_hash`

This supports end-to-end sequence reconstruction for flows such as:
`signin -> security_code -> trust -> account_login -> validate -> find_devices`.

### Local stack (Docker Compose)

An opinionated local dev/QA stack is provided under `ops/observability/`:

```bash
cd /Users/inean/Projects/Legacy/Sandbox/pyicloud
docker compose -f ops/observability/docker-compose.yml up -d
```

Exposed services:

- Grafana: `http://127.0.0.1:3000` (`admin` / `admin`)
- Prometheus: `http://127.0.0.1:9090`
- Tempo: `http://127.0.0.1:3200`
- Loki: `http://127.0.0.1:3100`

## HTTP endpoints

- `POST /v1/observability/promql`
- `POST /v1/observability/traceql`
- `POST /v1/observability/logql`

Request body:

```json
{
  "query": "up",
  "source": "optional-backend-hint",
  "start": 1710000000,
  "end": 1710000600,
  "step": "1m"
}
```

`start`, `end`, and `step` are optional as a group. If one is provided, all are required.

Response envelope:

```json
{
  "status": "success",
  "language": "promql",
  "data": {},
  "warnings": [],
  "source": "prometheus"
}
```

## Error mapping

- `UnsupportedQueryMode` -> `422 Unprocessable Entity`
- `BackendUnavailable` -> `503 Service Unavailable`
- `QueryExecutionFailed` -> `502 Bad Gateway`

## CLI commands

- `icloud observability promql --query 'up'`
- `icloud observability traceql --query '{ duration > 1s }' --start 1710000000 --end 1710000600 --step 1m`
- `icloud observability logql --query '{service="api"}'`
- `icloud observability flow --flow-id <flow-id> --format table|json`

`icloud observability flow` runs a LogQL query and renders a timeline sorted by event timestamp.
