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

## HTTP endpoints

- `POST /v1/observability/promql`
- `POST /v1/observability/traceql`
- `POST /v1/observability/logql`
- Alias: `POST /v1/observability/pronql` (normalized to `promql`)

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
- Alias: `icloud observability pronql --query 'up'`
