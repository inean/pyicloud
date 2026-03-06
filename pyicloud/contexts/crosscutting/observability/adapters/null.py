"""Deterministic no-backend observability adapter."""

from __future__ import annotations

from pyicloud.contexts.crosscutting.observability.contracts.observability import (
    LogQLQueryPort,
    ObservabilityInstantQueryRequest,
    ObservabilityLanguage,
    ObservabilityQueryEnvelope,
    ObservabilityRangeQueryRequest,
    PromQLQueryPort,
    TraceQLQueryPort,
)


class NullObservabilityAdapter(PromQLQueryPort, TraceQLQueryPort, LogQLQueryPort):
    """Return deterministic envelopes when no observability backend is configured."""

    def __init__(self, *, source: str = "null"):
        self._default_source = source

    def _envelope(
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
        data: dict[str, object] = {
            "mode": mode,
            "query": query,
            "resultType": "matrix" if mode == "range" else "vector",
            "result": [],
        }
        if mode == "range":
            data["range"] = {"start": start, "end": end, "step": step}
        return {
            "status": "unconfigured",
            "language": language,
            "data": data,
            "warnings": [
                "Observability adapter is unconfigured; returning deterministic empty result.",
            ],
            "source": source or self._default_source,
        }

    def query_promql(self, request: ObservabilityInstantQueryRequest) -> ObservabilityQueryEnvelope:
        return self._envelope(
            language="promql",
            mode="instant",
            query=str(request.get("query", "")),
            source=request.get("source"),
        )

    def query_promql_range(self, request: ObservabilityRangeQueryRequest) -> ObservabilityQueryEnvelope:
        return self._envelope(
            language="promql",
            mode="range",
            query=str(request.get("query", "")),
            source=request.get("source"),
            start=int(request.get("start", 0)),
            end=int(request.get("end", 0)),
            step=str(request.get("step", "")),
        )

    def query_traceql(self, request: ObservabilityInstantQueryRequest) -> ObservabilityQueryEnvelope:
        return self._envelope(
            language="traceql",
            mode="instant",
            query=str(request.get("query", "")),
            source=request.get("source"),
        )

    def query_traceql_range(self, request: ObservabilityRangeQueryRequest) -> ObservabilityQueryEnvelope:
        return self._envelope(
            language="traceql",
            mode="range",
            query=str(request.get("query", "")),
            source=request.get("source"),
            start=int(request.get("start", 0)),
            end=int(request.get("end", 0)),
            step=str(request.get("step", "")),
        )

    def query_logql(self, request: ObservabilityInstantQueryRequest) -> ObservabilityQueryEnvelope:
        return self._envelope(
            language="logql",
            mode="instant",
            query=str(request.get("query", "")),
            source=request.get("source"),
        )

    def query_logql_range(self, request: ObservabilityRangeQueryRequest) -> ObservabilityQueryEnvelope:
        return self._envelope(
            language="logql",
            mode="range",
            query=str(request.get("query", "")),
            source=request.get("source"),
            start=int(request.get("start", 0)),
            end=int(request.get("end", 0)),
            step=str(request.get("step", "")),
        )


__all__ = ["NullObservabilityAdapter"]
