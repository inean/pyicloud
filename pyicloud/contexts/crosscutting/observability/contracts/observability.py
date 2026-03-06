"""Ports and contracts for observability query operations."""

from __future__ import annotations

from typing import Any, Literal, Protocol, TypedDict

type ObservabilityLanguage = Literal["promql", "traceql", "logql"]


class ObservabilityInstantQueryRequest(TypedDict, total=False):
    query: str
    source: str | None


class ObservabilityRangeQueryRequest(TypedDict, total=False):
    query: str
    start: int
    end: int
    step: str
    source: str | None


class ObservabilityQueryEnvelope(TypedDict):
    status: str
    language: ObservabilityLanguage
    data: Any
    warnings: list[str]
    source: str


class PromQLQueryPort(Protocol):
    """
    Direction: outbound

    Purpose:
        This port isolates PromQL query execution from API-facing orchestration
        so application code does not depend on concrete backend clients.

        Implementations translate domain query intent into backend calls and map
        backend payloads to a stable response envelope for API and CLI callers.

    Implemented by: NullObservabilityAdapter, OTelObservabilityAdapter
    """

    def query_promql(self, request: ObservabilityInstantQueryRequest) -> ObservabilityQueryEnvelope:
        """
        ObservabilityApi calls this method to execute one PromQL instant query.

        The adapter translates query input to backend transport semantics and converts
        backend response payloads into a normalized observability envelope.

        Raises:
            BackendUnavailable: The selected backend cannot be reached.
            QueryExecutionFailed: The backend rejects or fails to execute the query.
        """

    def query_promql_range(self, request: ObservabilityRangeQueryRequest) -> ObservabilityQueryEnvelope:
        """
        ObservabilityApi calls this method to execute one PromQL range query.

        The adapter translates range boundaries and step values to backend request
        formats and maps backend responses to a stable domain envelope.

        Raises:
            BackendUnavailable: The selected backend cannot be reached.
            QueryExecutionFailed: The backend rejects or fails to execute the query.
        """


class TraceQLQueryPort(Protocol):
    """
    Direction: outbound

    Purpose:
        This port isolates TraceQL query execution from API-facing orchestration
        so application code does not depend on concrete tracing backends.

        Implementations translate domain query intent into backend calls and map
        backend payloads to a stable response envelope for API and CLI callers.

    Implemented by: NullObservabilityAdapter, OTelObservabilityAdapter
    """

    def query_traceql(self, request: ObservabilityInstantQueryRequest) -> ObservabilityQueryEnvelope:
        """
        ObservabilityApi calls this method to execute one TraceQL instant query.

        The adapter translates query input to backend transport semantics and converts
        backend response payloads into a normalized observability envelope.

        Raises:
            BackendUnavailable: The selected backend cannot be reached.
            QueryExecutionFailed: The backend rejects or fails to execute the query.
        """

    def query_traceql_range(self, request: ObservabilityRangeQueryRequest) -> ObservabilityQueryEnvelope:
        """
        ObservabilityApi calls this method to execute one TraceQL range query.

        The adapter translates range boundaries and step values to backend request
        formats and maps backend responses to a stable domain envelope.

        Raises:
            BackendUnavailable: The selected backend cannot be reached.
            QueryExecutionFailed: The backend rejects or fails to execute the query.
        """


class LogQLQueryPort(Protocol):
    """
    Direction: outbound

    Purpose:
        This port isolates LogQL query execution from API-facing orchestration
        so application code does not depend on concrete logging backends.

        Implementations translate domain query intent into backend calls and map
        backend payloads to a stable response envelope for API and CLI callers.

    Implemented by: NullObservabilityAdapter, OTelObservabilityAdapter
    """

    def query_logql(self, request: ObservabilityInstantQueryRequest) -> ObservabilityQueryEnvelope:
        """
        ObservabilityApi calls this method to execute one LogQL instant query.

        The adapter translates query input to backend transport semantics and converts
        backend response payloads into a normalized observability envelope.

        Raises:
            BackendUnavailable: The selected backend cannot be reached.
            QueryExecutionFailed: The backend rejects or fails to execute the query.
        """

    def query_logql_range(self, request: ObservabilityRangeQueryRequest) -> ObservabilityQueryEnvelope:
        """
        ObservabilityApi calls this method to execute one LogQL range query.

        The adapter translates range boundaries and step values to backend request
        formats and maps backend responses to a stable domain envelope.

        Raises:
            BackendUnavailable: The selected backend cannot be reached.
            QueryExecutionFailed: The backend rejects or fails to execute the query.
        """
