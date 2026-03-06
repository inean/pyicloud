"""Optional OTel-aligned observability adapter."""

from __future__ import annotations

import importlib
from collections.abc import Callable
from contextlib import contextmanager, nullcontext
from time import perf_counter
from typing import Any

import httpx

from pyicloud.contexts.crosscutting.observability.contracts.observability import (
    LogQLQueryPort,
    ObservabilityInstantQueryRequest,
    ObservabilityLanguage,
    ObservabilityQueryEnvelope,
    ObservabilityRangeQueryRequest,
    PromQLQueryPort,
    TraceQLQueryPort,
)
from pyicloud.contexts.crosscutting.telemetry.adapters.upstream_probe import (
    get_upstream_probe,
    upstream_capture_body_max_bytes,
)
from pyicloud.contexts.crosscutting.telemetry.contracts.upstream_probe import UpstreamTrafficProbePort
from pyicloud.domain import BackendUnavailable, QueryExecutionFailed
from pyicloud.platform.telemetry.upstream import (
    bind_upstream_context,
    build_error_event,
    build_request_event,
    build_response_event,
)

OTEL_DEPENDENCY_ERROR = (
    "OTel observability adapter requires optional dependencies. Install with `uv sync --extra otel` and retry."
)


def ensure_otel_dependencies() -> None:
    """Fail fast when the otel adapter is explicitly selected without optional deps."""
    try:
        importlib.import_module("opentelemetry.trace")
    except ModuleNotFoundError as err:
        raise RuntimeError(OTEL_DEPENDENCY_ERROR) from err


class OTelObservabilityAdapter(PromQLQueryPort, TraceQLQueryPort, LogQLQueryPort):
    """Execute observability queries against backend APIs with optional tracing spans."""

    def __init__(
        self,
        *,
        promql_endpoint: str | None,
        traceql_endpoint: str | None,
        logql_endpoint: str | None,
        timeout_seconds: float = 10.0,
        client_factory: Callable[[], httpx.Client] | None = None,
        probe: UpstreamTrafficProbePort | None = None,
        probe_body_max_bytes: int | None = None,
    ):
        self._endpoints = {
            "promql": promql_endpoint,
            "traceql": traceql_endpoint,
            "logql": logql_endpoint,
        }
        self._timeout_seconds = timeout_seconds
        self._client_factory = client_factory
        self._probe = probe or get_upstream_probe()
        self._probe_body_max_bytes = (
            int(probe_body_max_bytes) if probe_body_max_bytes is not None else upstream_capture_body_max_bytes()
        )

    @contextmanager
    def _maybe_span(self, *, language: ObservabilityLanguage, mode: str):
        name = f"observability.{language}.{mode}"
        try:
            trace = importlib.import_module("opentelemetry.trace")
        except ModuleNotFoundError:
            with nullcontext():
                yield
            return
        tracer = trace.get_tracer("pyicloud.observability")
        with tracer.start_as_current_span(name):
            yield

    def _build_client(self) -> httpx.Client:
        if self._client_factory is not None:
            return self._client_factory()
        return httpx.Client(timeout=self._timeout_seconds)

    def _build_request(
        self,
        *,
        endpoint: str,
        query: str,
        source: str | None,
        start: int | None = None,
        end: int | None = None,
        step: str | None = None,
    ) -> httpx.Request:
        params: dict[str, str | int] = {"query": query}
        if source:
            params["source"] = source
        if start is not None:
            params["start"] = start
        if end is not None:
            params["end"] = end
        if step is not None:
            params["step"] = step
        return httpx.Request("GET", endpoint, params=params)

    def _execute(
        self,
        *,
        language: ObservabilityLanguage,
        mode: str,
        query: str,
        source: str | None,
        start: int | None = None,
        end: int | None = None,
        step: str | None = None,
    ) -> ObservabilityQueryEnvelope:
        endpoint = self._endpoints.get(language)
        if not endpoint:
            raise BackendUnavailable(f"Missing backend endpoint for {language}")

        request = self._build_request(
            endpoint=endpoint,
            query=query,
            source=source,
            start=start,
            end=end,
            step=step,
        )

        with bind_upstream_context(operation=f"observability.{language}", step=f"{language}_{mode}"):
            request_event = build_request_event(
                request=request,
                body_max_bytes=self._probe_body_max_bytes,
            )
            request_event["target_service"] = "observability.backend"
            request_event["step"] = f"{language}_{mode}"
            self._probe.on_request(request_event)

            started = perf_counter()
            try:
                with self._maybe_span(language=language, mode=mode):
                    with self._build_client() as client:
                        response = client.send(request)
            except httpx.HTTPError as err:
                self._probe.on_error(
                    build_error_event(
                        request_event=request_event,
                        error=err,
                        duration_ms=(perf_counter() - started) * 1000.0,
                        body_max_bytes=self._probe_body_max_bytes,
                    )
                )
                raise BackendUnavailable(f"{language} backend unavailable") from err

            duration_ms = (perf_counter() - started) * 1000.0

            if response.status_code in {502, 503, 504}:
                err = BackendUnavailable(f"{language} backend unavailable ({response.status_code})")
                self._probe.on_error(
                    build_error_event(
                        request_event=request_event,
                        error=err,
                        duration_ms=duration_ms,
                        response=response,
                        body_max_bytes=self._probe_body_max_bytes,
                    )
                )
                raise err
            if response.status_code >= 400:
                err = QueryExecutionFailed(f"{language} backend rejected query ({response.status_code})")
                self._probe.on_error(
                    build_error_event(
                        request_event=request_event,
                        error=err,
                        duration_ms=duration_ms,
                        response=response,
                        body_max_bytes=self._probe_body_max_bytes,
                    )
                )
                raise err

            try:
                payload = response.json()
            except ValueError as err:
                query_err = QueryExecutionFailed(f"{language} backend returned non-JSON payload")
                self._probe.on_error(
                    build_error_event(
                        request_event=request_event,
                        error=query_err,
                        duration_ms=duration_ms,
                        response=response,
                        body_max_bytes=self._probe_body_max_bytes,
                    )
                )
                raise query_err from err

            if not isinstance(payload, dict):
                query_err = QueryExecutionFailed(f"{language} backend returned unexpected payload shape")
                self._probe.on_error(
                    build_error_event(
                        request_event=request_event,
                        error=query_err,
                        duration_ms=duration_ms,
                        response=response,
                        body_max_bytes=self._probe_body_max_bytes,
                    )
                )
                raise query_err

            self._probe.on_response(
                build_response_event(
                    request_event=request_event,
                    response=response,
                    duration_ms=duration_ms,
                    body_max_bytes=self._probe_body_max_bytes,
                )
            )

        warnings_raw = payload.get("warnings", [])
        if not isinstance(warnings_raw, list):
            warnings_raw = [str(warnings_raw)]
        warnings = [str(item) for item in warnings_raw]
        status = str(payload.get("status", "success"))
        data: Any = payload.get("data", payload)
        resolved_source = str(payload.get("source") or source or endpoint)
        return {
            "status": status,
            "language": language,
            "data": data,
            "warnings": warnings,
            "source": resolved_source,
        }

    def query_promql(self, request: ObservabilityInstantQueryRequest) -> ObservabilityQueryEnvelope:
        return self._execute(
            language="promql",
            mode="instant",
            query=str(request.get("query", "")),
            source=request.get("source"),
        )

    def query_promql_range(self, request: ObservabilityRangeQueryRequest) -> ObservabilityQueryEnvelope:
        return self._execute(
            language="promql",
            mode="range",
            query=str(request.get("query", "")),
            source=request.get("source"),
            start=int(request.get("start", 0)),
            end=int(request.get("end", 0)),
            step=str(request.get("step", "")),
        )

    def query_traceql(self, request: ObservabilityInstantQueryRequest) -> ObservabilityQueryEnvelope:
        return self._execute(
            language="traceql",
            mode="instant",
            query=str(request.get("query", "")),
            source=request.get("source"),
        )

    def query_traceql_range(self, request: ObservabilityRangeQueryRequest) -> ObservabilityQueryEnvelope:
        return self._execute(
            language="traceql",
            mode="range",
            query=str(request.get("query", "")),
            source=request.get("source"),
            start=int(request.get("start", 0)),
            end=int(request.get("end", 0)),
            step=str(request.get("step", "")),
        )

    def query_logql(self, request: ObservabilityInstantQueryRequest) -> ObservabilityQueryEnvelope:
        return self._execute(
            language="logql",
            mode="instant",
            query=str(request.get("query", "")),
            source=request.get("source"),
        )

    def query_logql_range(self, request: ObservabilityRangeQueryRequest) -> ObservabilityQueryEnvelope:
        return self._execute(
            language="logql",
            mode="range",
            query=str(request.get("query", "")),
            source=request.get("source"),
            start=int(request.get("start", 0)),
            end=int(request.get("end", 0)),
            step=str(request.get("step", "")),
        )


__all__ = ["OTelObservabilityAdapter", "OTEL_DEPENDENCY_ERROR", "ensure_otel_dependencies"]
