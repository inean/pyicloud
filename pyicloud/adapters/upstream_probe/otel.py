"""OTel-backed upstream traffic probe adapter."""

from __future__ import annotations

import importlib
import json
import logging
from typing import Any

from pyicloud.ports import UpstreamErrorEvent, UpstreamRequestEvent, UpstreamResponseEvent, UpstreamTrafficProbePort

OTEL_UPSTREAM_DEPENDENCY_ERROR = (
    "OTel upstream probe requires optional dependencies. Install with `uv sync --extra otel` and retry."
)


def ensure_otel_upstream_dependencies() -> None:
    """Fail fast when the OTel upstream probe is selected without optional deps."""
    try:
        importlib.import_module("opentelemetry.trace")
        importlib.import_module("opentelemetry.metrics")
    except ModuleNotFoundError as err:
        raise RuntimeError(OTEL_UPSTREAM_DEPENDENCY_ERROR) from err


class OTelUpstreamTrafficProbeAdapter(UpstreamTrafficProbePort):
    """Emit upstream probe events as OTel spans, metrics, and structured logs."""

    def __init__(self):
        trace = importlib.import_module("opentelemetry.trace")
        metrics = importlib.import_module("opentelemetry.metrics")

        self._tracer = trace.get_tracer("pyicloud.upstream")
        self._meter = metrics.get_meter("pyicloud.upstream")

        self._request_counter = self._meter.create_counter(
            "pyicloud_upstream_requests_total",
            unit="1",
            description="Total number of upstream requests by outcome and step",
        )
        self._request_duration = self._meter.create_histogram(
            "pyicloud_upstream_request_duration_seconds",
            unit="s",
            description="Upstream request duration distribution",
        )
        self._request_bytes = self._meter.create_histogram(
            "pyicloud_upstream_request_bytes",
            unit="By",
            description="Upstream request payload size",
        )
        self._response_bytes = self._meter.create_histogram(
            "pyicloud_upstream_response_bytes",
            unit="By",
            description="Upstream response payload size",
        )
        self._retries_counter = self._meter.create_counter(
            "pyicloud_upstream_retries_total",
            unit="1",
            description="Total number of upstream retry attempts",
        )

        self._logger = logging.getLogger("pyicloud.upstream_probe")

    @staticmethod
    def _labels(event: UpstreamResponseEvent | UpstreamErrorEvent) -> dict[str, str]:
        return {
            "target_service": event["target_service"],
            "method": event["method"],
            "status_family": event["status_family"],
            "outcome": event["outcome"],
            "operation": event["operation"],
            "step": event["step"],
        }

    @staticmethod
    def _span_attributes(event: UpstreamResponseEvent | UpstreamErrorEvent) -> dict[str, Any]:
        attrs: dict[str, Any] = {
            "pyicloud.flow_id": event["flow_id"],
            "pyicloud.operation": event["operation"],
            "pyicloud.step": event["step"],
            "pyicloud.account_hash": event["account_hash"],
            "http.method": event["method"],
            "server.address": event["host"],
            "url.path": event["path"],
            "duration_ms": float(event["duration_ms"]),
            "target_service": event["target_service"],
        }
        if event.get("status_code") is not None:
            attrs["http.status_code"] = int(event["status_code"])
        apple_request_id = event.get("apple_request_id")
        if apple_request_id:
            attrs["apple.request_id"] = apple_request_id
        if event["outcome"] == "error":
            attrs["error.type"] = str(event["error_type"])
        return attrs

    def _record_metrics(self, event: UpstreamResponseEvent | UpstreamErrorEvent) -> None:
        labels = self._labels(event)

        self._request_counter.add(1, attributes=labels)
        self._request_duration.record(float(event["duration_ms"]) / 1000.0, attributes=labels)
        self._request_bytes.record(int(event["request_bytes"]), attributes=labels)
        self._response_bytes.record(int(event["response_bytes"]), attributes=labels)

        attempt = int(event.get("attempt", 1))
        if attempt > 1:
            self._retries_counter.add(attempt - 1, attributes=labels)

    def _log_event(self, event: UpstreamResponseEvent | UpstreamErrorEvent) -> None:
        log_payload = {
            "timestamp": event["timestamp"],
            "level": "ERROR" if event["outcome"] == "error" else "INFO",
            "message": "upstream_http",
            "trace_id": None,
            "span_id": None,
            "request_id": event.get("apple_request_id"),
            "component": "pyicloud.upstream",
            "pyicloud.flow_id": event["flow_id"],
            "pyicloud.operation": event["operation"],
            "pyicloud.step": event["step"],
            "pyicloud.account_hash": event["account_hash"],
            "target_service": event["target_service"],
            "method": event["method"],
            "host": event["host"],
            "path": event["path"],
            "status_code": event.get("status_code"),
            "status_family": event["status_family"],
            "outcome": event["outcome"],
            "duration_ms": event["duration_ms"],
            "attempt": event["attempt"],
            "request_bytes": event["request_bytes"],
            "response_bytes": event["response_bytes"],
            "request_headers": event["request_headers"],
            "request_cookies": event["request_cookies"],
            "request_body": event["request_body"],
            "response_headers": event["response_headers"],
            "response_cookies": event["response_cookies"],
            "response_body": event["response_body"],
        }
        if event["outcome"] == "error":
            log_payload["error_type"] = event["error_type"]
            log_payload["error_message"] = event["error_message"]
        self._logger.info(json.dumps(log_payload, separators=(",", ":"), default=str))

    def on_request(self, event: UpstreamRequestEvent) -> None:  # noqa: ARG002
        # Request-level logging happens at response/error time to include complete timing and status metadata.
        return None

    def on_response(self, event: UpstreamResponseEvent) -> None:
        self._record_metrics(event)
        with self._tracer.start_as_current_span("pyicloud.upstream.http") as span:
            for key, value in self._span_attributes(event).items():
                span.set_attribute(key, value)
        self._log_event(event)

    def on_error(self, event: UpstreamErrorEvent) -> None:
        self._record_metrics(event)
        with self._tracer.start_as_current_span("pyicloud.upstream.http") as span:
            for key, value in self._span_attributes(event).items():
                span.set_attribute(key, value)
            span.set_attribute("error", True)
            span.set_status(
                importlib.import_module("opentelemetry.trace").Status(  # type: ignore[call-arg]
                    importlib.import_module("opentelemetry.trace").StatusCode.ERROR,
                    str(event["error_message"]),
                )
            )
        self._log_event(event)
