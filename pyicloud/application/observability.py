"""Application facade for observability query operations."""

from __future__ import annotations

from pyicloud.domain import UnsupportedQueryMode
from pyicloud.ports import (
    LogQLQueryPort,
    ObservabilityLanguage,
    ObservabilityQueryEnvelope,
    PromQLQueryPort,
    TraceQLQueryPort,
)


class ObservabilityApi:
    """Route observability queries to language-specific outbound ports."""

    def __init__(
        self,
        *,
        promql: PromQLQueryPort,
        traceql: TraceQLQueryPort,
        logql: LogQLQueryPort,
    ):
        self._promql = promql
        self._traceql = traceql
        self._logql = logql

    @staticmethod
    def normalize_language(language: str) -> ObservabilityLanguage:
        clean = language.strip().lower()
        if clean in {"promql", "traceql", "logql"}:
            return clean
        raise UnsupportedQueryMode(f"Unsupported observability language: {language}")

    def instant_query(
        self,
        *,
        language: str,
        query: str,
        source: str | None = None,
    ) -> ObservabilityQueryEnvelope:
        normalized = self.normalize_language(language)
        request = {"query": query, "source": source}
        if normalized == "promql":
            return self._promql.query_promql(request)
        if normalized == "traceql":
            return self._traceql.query_traceql(request)
        return self._logql.query_logql(request)

    def range_query(
        self,
        *,
        language: str,
        query: str,
        start: int,
        end: int,
        step: str,
        source: str | None = None,
    ) -> ObservabilityQueryEnvelope:
        normalized = self.normalize_language(language)
        request = {"query": query, "start": start, "end": end, "step": step, "source": source}
        if normalized == "promql":
            return self._promql.query_promql_range(request)
        if normalized == "traceql":
            return self._traceql.query_traceql_range(request)
        return self._logql.query_logql_range(request)
