"""Optional OTel-aligned observability adapter."""

from __future__ import annotations

import importlib
from collections.abc import Callable
from contextlib import contextmanager, nullcontext
from typing import Any

import httpx

from pyicloud.domain import BackendUnavailable, QueryExecutionFailed
from pyicloud.ports import (
    LogQLQueryPort,
    ObservabilityInstantQueryRequest,
    ObservabilityLanguage,
    ObservabilityQueryEnvelope,
    ObservabilityRangeQueryRequest,
    PromQLQueryPort,
    TraceQLQueryPort,
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
    ):
        self._endpoints = {
            "promql": promql_endpoint,
            "traceql": traceql_endpoint,
            "logql": logql_endpoint,
        }
        self._timeout_seconds = timeout_seconds
        self._client_factory = client_factory

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

        params: dict[str, str | int] = {"query": query}
        if source:
            params["source"] = source
        if mode == "range":
            assert start is not None
            assert end is not None
            assert step is not None
            params["start"] = start
            params["end"] = end
            params["step"] = step

        try:
            with self._maybe_span(language=language, mode=mode):
                with self._build_client() as client:
                    response = client.get(endpoint, params=params)
        except httpx.HTTPError as err:
            raise BackendUnavailable(f"{language} backend unavailable") from err

        if response.status_code in {502, 503, 504}:
            raise BackendUnavailable(f"{language} backend unavailable ({response.status_code})")
        if response.status_code >= 400:
            raise QueryExecutionFailed(f"{language} backend rejected query ({response.status_code})")

        try:
            payload = response.json()
        except ValueError as err:
            raise QueryExecutionFailed(f"{language} backend returned non-JSON payload") from err

        if not isinstance(payload, dict):
            raise QueryExecutionFailed(f"{language} backend returned unexpected payload shape")

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
