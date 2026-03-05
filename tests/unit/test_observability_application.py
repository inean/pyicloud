from __future__ import annotations

import pytest

from pyicloud.adapters.observability import NullObservabilityAdapter
from pyicloud.application.observability import ObservabilityApi
from pyicloud.domain import UnsupportedQueryMode


def _build_service() -> ObservabilityApi:
    adapter = NullObservabilityAdapter()
    return ObservabilityApi(promql=adapter, traceql=adapter, logql=adapter)


def test_observability_language_normalization_accepts_pronql_alias() -> None:
    assert ObservabilityApi.normalize_language("pronql") == "promql"


def test_observability_language_normalization_rejects_unknown_language() -> None:
    with pytest.raises(UnsupportedQueryMode):
        ObservabilityApi.normalize_language("sql")


def test_observability_application_routes_instant_query() -> None:
    service = _build_service()

    promql = service.instant_query(language="promql", query="up")
    pronql = service.instant_query(language="pronql", query="up")
    traceql = service.instant_query(language="traceql", query='{ trace_id != "" }')

    assert promql["language"] == "promql"
    assert pronql["language"] == "promql"
    assert traceql["language"] == "traceql"


def test_observability_application_routes_range_query() -> None:
    service = _build_service()

    result = service.range_query(
        language="logql",
        query='{service="api"}',
        start=1710000000,
        end=1710000300,
        step="30s",
    )

    assert result["language"] == "logql"
    assert result["data"]["resultType"] == "matrix"
