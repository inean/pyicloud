from __future__ import annotations

import httpx
import pytest

from pyicloud.adapters.observability.otel import OTelObservabilityAdapter
from pyicloud.contexts.crosscutting.observability.application.observability import ObservabilityApi


@pytest.mark.integration
def test_otel_adapter_uses_mocked_backend_endpoints_without_network():
    seen_requests: list[tuple[str, dict[str, str]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        params = {key: value for key, value in request.url.params.items()}
        seen_requests.append((request.url.path, params))
        return httpx.Response(
            status_code=200,
            json={
                "status": "success",
                "data": {
                    "path": request.url.path,
                    "query": params.get("query", ""),
                    "mode": "range" if "start" in params else "instant",
                },
                "warnings": [],
            },
        )

    adapter = OTelObservabilityAdapter(
        promql_endpoint="https://observability.test/promql",
        traceql_endpoint="https://observability.test/traceql",
        logql_endpoint="https://observability.test/logql",
        client_factory=lambda: httpx.Client(transport=httpx.MockTransport(handler)),
    )
    service = ObservabilityApi(promql=adapter, traceql=adapter, logql=adapter)

    promql = service.instant_query(language="promql", query="up")
    traceql = service.range_query(
        language="traceql",
        query="{ duration > 1s }",
        start=1710000000,
        end=1710000600,
        step="1m",
    )
    logql = service.instant_query(language="logql", query='{service="api"}')

    assert promql["status"] == "success"
    assert promql["data"]["path"] == "/promql"
    assert traceql["data"]["mode"] == "range"
    assert logql["data"]["path"] == "/logql"
    assert seen_requests == [
        ("/promql", {"query": "up"}),
        (
            "/traceql",
            {"query": "{ duration > 1s }", "start": "1710000000", "end": "1710000600", "step": "1m"},
        ),
        ("/logql", {"query": '{service="api"}'}),
    ]
