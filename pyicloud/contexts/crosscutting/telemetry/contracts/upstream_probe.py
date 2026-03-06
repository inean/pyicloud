"""Ports and contracts for upstream HTTP traffic inspection."""

from __future__ import annotations

from typing import Any, Literal, Protocol, TypedDict

type UpstreamOutcome = Literal["success", "error"]


class UpstreamRequestEvent(TypedDict):
    timestamp: float
    flow_id: str
    operation: str
    step: str
    account_hash: str
    target_service: str
    method: str
    host: str
    path: str
    attempt: int
    request_headers: dict[str, Any]
    request_cookies: dict[str, Any]
    request_body: Any
    request_bytes: int


class UpstreamResponseEvent(UpstreamRequestEvent):
    outcome: Literal["success"]
    status_code: int
    status_family: str
    duration_ms: float
    response_headers: dict[str, Any]
    response_cookies: dict[str, Any]
    response_body: Any
    response_bytes: int
    apple_request_id: str | None


class UpstreamErrorEvent(UpstreamRequestEvent):
    outcome: Literal["error"]
    duration_ms: float
    error_type: str
    error_message: str
    status_code: int | None
    status_family: str
    response_headers: dict[str, Any]
    response_cookies: dict[str, Any]
    response_body: Any
    response_bytes: int
    apple_request_id: str | None


class UpstreamTrafficProbePort(Protocol):
    """
    Direction: outbound

    Purpose:
        This port isolates upstream traffic inspection from transport clients so
        auth/session and legacy service code do not depend on concrete telemetry SDKs.

        Implementations translate normalized request/response/error events into
        tracing, metrics, and logs while preserving safe redaction boundaries.

    Implemented by: NullUpstreamTrafficProbeAdapter, OTelUpstreamTrafficProbeAdapter
    """

    def on_request(self, event: UpstreamRequestEvent) -> None:
        """
        Transport adapters call this method before sending one upstream HTTP request.

        The probe adapter maps request metadata and sanitized payload fields into
        backend-specific telemetry records without exposing transport internals.

        Raises:
            RuntimeError: Probe initialization or export pipeline is misconfigured.
        """

    def on_response(self, event: UpstreamResponseEvent) -> None:
        """
        Transport adapters call this method after one upstream request succeeds.

        The probe adapter translates latency, status, and sanitized response data
        into stable span/metric/log signals for downstream inspection tooling.

        Raises:
            RuntimeError: Probe initialization or export pipeline is misconfigured.
        """

    def on_error(self, event: UpstreamErrorEvent) -> None:
        """
        Transport adapters call this method when one upstream request fails.

        The probe adapter converts error context into failure telemetry so callers
        can correlate request intent with transport or upstream failure outcomes.

        Raises:
            RuntimeError: Probe initialization or export pipeline is misconfigured.
        """
