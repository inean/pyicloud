from __future__ import annotations

import httpx
import pytest

from pyicloud.adapters.observability.otel import (
    OTelObservabilityAdapter,
    ensure_otel_dependencies,
)
from pyicloud.domain import BackendUnavailable, QueryExecutionFailed


def _build_client_with_status(status_code: int) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        return httpx.Response(status_code=status_code, json={"status": "error"})

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_ensure_otel_dependencies_fails_with_clear_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_import_module(name: str):
        if name == "opentelemetry.trace":
            raise ModuleNotFoundError(name)
        return object()

    monkeypatch.setattr("pyicloud.adapters.observability.otel.importlib.import_module", fake_import_module)

    with pytest.raises(RuntimeError, match="optional dependencies"):
        ensure_otel_dependencies()


def test_otel_adapter_requires_endpoint_for_language() -> None:
    adapter = OTelObservabilityAdapter(
        promql_endpoint=None,
        traceql_endpoint="https://example.test/traceql",
        logql_endpoint="https://example.test/logql",
    )

    with pytest.raises(BackendUnavailable, match="Missing backend endpoint"):
        adapter.query_promql({"query": "up"})


def test_otel_adapter_maps_backend_4xx_to_execution_failure() -> None:
    adapter = OTelObservabilityAdapter(
        promql_endpoint="https://example.test/promql",
        traceql_endpoint="https://example.test/traceql",
        logql_endpoint="https://example.test/logql",
        client_factory=lambda: _build_client_with_status(400),
    )

    with pytest.raises(QueryExecutionFailed, match="rejected query"):
        adapter.query_promql({"query": "up"})


def test_otel_adapter_returns_envelope_on_success() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["query"] == "up"
        return httpx.Response(
            status_code=200,
            json={
                "status": "success",
                "data": {"resultType": "vector", "result": []},
                "warnings": ["partial data"],
                "source": "tempo",
            },
        )

    adapter = OTelObservabilityAdapter(
        promql_endpoint="https://example.test/promql",
        traceql_endpoint="https://example.test/traceql",
        logql_endpoint="https://example.test/logql",
        client_factory=lambda: httpx.Client(transport=httpx.MockTransport(handler)),
    )

    result = adapter.query_promql({"query": "up"})

    assert result["language"] == "promql"
    assert result["status"] == "success"
    assert result["source"] == "tempo"
    assert result["warnings"] == ["partial data"]
