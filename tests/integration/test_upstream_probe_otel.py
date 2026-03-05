from __future__ import annotations

import json
import logging

import pytest

from pyicloud.adapters.upstream_probe.otel import OTelUpstreamTrafficProbeAdapter


class _CounterRecorder:
    def __init__(self) -> None:
        self.calls: list[tuple[float, dict[str, str]]] = []

    def add(self, value: float, *, attributes: dict[str, str]) -> None:
        self.calls.append((value, attributes))


class _HistogramRecorder:
    def __init__(self) -> None:
        self.calls: list[tuple[float, dict[str, str]]] = []

    def record(self, value: float, *, attributes: dict[str, str]) -> None:
        self.calls.append((value, attributes))


@pytest.mark.integration
def test_otel_upstream_probe_emits_spans_metrics_and_logs(caplog: pytest.LogCaptureFixture):
    trace = pytest.importorskip("opentelemetry.trace")
    sdk_trace = pytest.importorskip("opentelemetry.sdk.trace")
    sdk_export = pytest.importorskip("opentelemetry.sdk.trace.export")
    in_memory = pytest.importorskip("opentelemetry.sdk.trace.export.in_memory_span_exporter")

    provider = sdk_trace.TracerProvider()
    exporter = in_memory.InMemorySpanExporter()
    provider.add_span_processor(sdk_export.SimpleSpanProcessor(exporter))
    trace.set_tracer_provider(provider)

    adapter = OTelUpstreamTrafficProbeAdapter()
    adapter._request_counter = _CounterRecorder()  # type: ignore[assignment]
    adapter._request_duration = _HistogramRecorder()  # type: ignore[assignment]
    adapter._request_bytes = _HistogramRecorder()  # type: ignore[assignment]
    adapter._response_bytes = _HistogramRecorder()  # type: ignore[assignment]
    adapter._retries_counter = _CounterRecorder()  # type: ignore[assignment]

    event = {
        "timestamp": 1710000000.0,
        "flow_id": "flow-123",
        "operation": "devices.list",
        "step": "find_devices",
        "account_hash": "abc123",
        "target_service": "apple.findmy",
        "method": "POST",
        "host": "p44-fmip.icloud.com",
        "path": "/fmipservice/client/web/refreshClient",
        "attempt": 2,
        "request_headers": {},
        "request_cookies": {},
        "request_body": {"truncated": False},
        "request_bytes": 120,
        "outcome": "success",
        "status_code": 200,
        "status_family": "2xx",
        "duration_ms": 45.0,
        "response_headers": {},
        "response_cookies": {},
        "response_body": {"truncated": False},
        "response_bytes": 240,
        "apple_request_id": "req-1",
    }

    with caplog.at_level(logging.INFO, logger="pyicloud.upstream_probe"):
        adapter.on_response(event)

    spans = exporter.get_finished_spans()
    assert len(spans) == 1
    span = spans[0]
    assert span.name == "pyicloud.upstream.http"
    assert span.attributes["pyicloud.flow_id"] == "flow-123"
    assert span.attributes["pyicloud.step"] == "find_devices"

    assert adapter._request_counter.calls  # type: ignore[attr-defined]
    assert adapter._request_duration.calls  # type: ignore[attr-defined]
    assert adapter._request_bytes.calls  # type: ignore[attr-defined]
    assert adapter._response_bytes.calls  # type: ignore[attr-defined]
    assert adapter._retries_counter.calls == [(1, adapter._request_counter.calls[0][1])]  # type: ignore[attr-defined]

    assert caplog.records
    payload = json.loads(caplog.records[-1].message)
    assert payload["pyicloud.flow_id"] == "flow-123"
    assert payload["component"] == "pyicloud.upstream"
