from __future__ import annotations

from pyicloud.adapters.observability import NullObservabilityAdapter


def test_null_adapter_returns_deterministic_instant_envelope() -> None:
    adapter = NullObservabilityAdapter()

    left = adapter.query_promql({"query": "up"})
    right = adapter.query_promql({"query": "up"})

    assert left == right
    assert left["status"] == "unconfigured"
    assert left["language"] == "promql"
    assert left["data"]["resultType"] == "vector"
    assert left["source"] == "null"


def test_null_adapter_range_envelope_includes_boundaries() -> None:
    adapter = NullObservabilityAdapter(source="local-null")
    result = adapter.query_traceql_range(
        {
            "query": "{ duration > 1s }",
            "start": 1710000000,
            "end": 1710000600,
            "step": "1m",
        }
    )

    assert result["status"] == "unconfigured"
    assert result["language"] == "traceql"
    assert result["data"]["resultType"] == "matrix"
    assert result["data"]["range"] == {"start": 1710000000, "end": 1710000600, "step": "1m"}
    assert result["source"] == "local-null"
