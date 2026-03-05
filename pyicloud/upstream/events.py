"""Event builders for upstream request/response/error probe records."""

from __future__ import annotations

from time import time
from urllib.parse import urlparse

import httpx

from pyicloud.constants import AppleHeaders
from pyicloud.ports import UpstreamErrorEvent, UpstreamRequestEvent, UpstreamResponseEvent

from .classification import classify_upstream_request
from .context import current_upstream_context, ensure_upstream_context
from .sanitize import sanitize_body, sanitize_headers


def _status_family(status_code: int | None) -> str:
    if status_code is None:
        return "n/a"
    return f"{int(status_code) // 100}xx"


def build_request_event(
    *,
    request: httpx.Request,
    body_max_bytes: int,
    attempt: int = 1,
) -> UpstreamRequestEvent:
    """Build a normalized request event from one upstream HTTP request."""
    context = ensure_upstream_context()
    parsed = urlparse(str(request.url))
    target_service, classified_step = classify_upstream_request(method=request.method, url=str(request.url))
    active_step = context.get("step") or classified_step

    request_headers, request_cookies = sanitize_headers(dict(request.headers.items()))
    request_body, request_bytes = sanitize_body(
        body=request.content,
        content_type=request.headers.get("content-type"),
        max_bytes=body_max_bytes,
    )

    return {
        "timestamp": time(),
        "flow_id": context["flow_id"],
        "operation": context.get("operation", "unknown"),
        "step": active_step,
        "account_hash": context.get("account_hash", "anonymous"),
        "target_service": target_service,
        "method": request.method.upper(),
        "host": parsed.hostname or "",
        "path": parsed.path or "/",
        "attempt": max(1, int(attempt)),
        "request_headers": request_headers,
        "request_cookies": request_cookies,
        "request_body": request_body,
        "request_bytes": request_bytes,
    }


def build_response_event(
    *,
    request_event: UpstreamRequestEvent,
    response: httpx.Response,
    duration_ms: float,
    body_max_bytes: int,
) -> UpstreamResponseEvent:
    """Build a normalized success event from one upstream HTTP response."""
    response_headers, response_cookies = sanitize_headers(dict(response.headers.items()))

    if response.is_stream_consumed:
        response_body, response_bytes = sanitize_body(
            body=response.content,
            content_type=response.headers.get("content-type"),
            max_bytes=body_max_bytes,
        )
    else:
        declared_length = int(response.headers.get("content-length", "0") or 0)
        response_body = {
            "stream": True,
            "length": declared_length,
            "truncated": declared_length > body_max_bytes,
        }
        response_bytes = declared_length

    return {
        **request_event,
        "outcome": "success",
        "status_code": response.status_code,
        "status_family": _status_family(response.status_code),
        "duration_ms": duration_ms,
        "response_headers": response_headers,
        "response_cookies": response_cookies,
        "response_body": response_body,
        "response_bytes": response_bytes,
        "apple_request_id": response.headers.get(AppleHeaders.REQUEST_ID),
    }


def build_error_event(
    *,
    request_event: UpstreamRequestEvent,
    error: Exception,
    duration_ms: float,
    response: httpx.Response | None = None,
    body_max_bytes: int,
) -> UpstreamErrorEvent:
    """Build a normalized error event for one upstream request failure."""
    status_code: int | None = None
    response_headers: dict[str, object] = {}
    response_cookies: dict[str, object] = {}
    response_body: object = None
    response_bytes = 0
    apple_request_id: str | None = None

    if response is not None:
        status_code = response.status_code
        response_headers, response_cookies = sanitize_headers(dict(response.headers.items()))
        apple_request_id = response.headers.get(AppleHeaders.REQUEST_ID)
        if response.is_stream_consumed:
            response_body, response_bytes = sanitize_body(
                body=response.content,
                content_type=response.headers.get("content-type"),
                max_bytes=body_max_bytes,
            )
        else:
            declared_length = int(response.headers.get("content-length", "0") or 0)
            response_body = {
                "stream": True,
                "length": declared_length,
                "truncated": declared_length > body_max_bytes,
            }
            response_bytes = declared_length

    return {
        **request_event,
        "outcome": "error",
        "duration_ms": duration_ms,
        "error_type": type(error).__name__,
        "error_message": str(error),
        "status_code": status_code,
        "status_family": _status_family(status_code),
        "response_headers": response_headers,
        "response_cookies": response_cookies,
        "response_body": response_body,
        "response_bytes": response_bytes,
        "apple_request_id": apple_request_id,
    }


def hydrate_from_context(
    *, operation: str | None = None, username: str | None = None, flow_id: str | None = None
) -> str:
    """Ensure minimum context and return active flow id."""
    context = ensure_upstream_context(operation=operation, username=username, flow_id=flow_id)
    return context["flow_id"]


def snapshot_context() -> dict[str, str]:
    """Return a copy of current context for diagnostics."""
    return current_upstream_context()
