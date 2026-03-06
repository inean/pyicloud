"""API telemetry middleware for route-level instrumentation."""

from __future__ import annotations

import json
import logging
import os
import random
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from time import perf_counter
from uuid import uuid4

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

LOGGER = logging.getLogger("pyicloud.telemetry")


def telemetry_enabled() -> bool:
    raw = os.getenv("PYICLOUD_TELEMETRY_ENABLED", "true").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def telemetry_sample_rate() -> float:
    raw = os.getenv("PYICLOUD_TELEMETRY_SAMPLE_RATE", "1.0").strip()
    try:
        value = float(raw)
    except ValueError:
        return 1.0
    return min(max(value, 0.0), 1.0)


@dataclass(frozen=True)
class ApiTelemetryEvent:
    timestamp: str
    level: str
    message: str
    trace_id: str | None
    span_id: str | None
    request_id: str
    component: str
    method: str
    route: str
    status: int
    duration_ms: float
    request_size_bytes: int | None
    response_size_bytes: int | None
    error: str | None


class ApiTelemetryMiddleware(BaseHTTPMiddleware):
    """Emit structured telemetry for every API request."""

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        sample = telemetry_sample_rate()
        if sample <= 0.0 or random.random() > sample:
            return await call_next(request)

        started = perf_counter()
        request_id = request.headers.get("x-request-id", str(uuid4()))
        trace_id = request.headers.get("x-trace-id")
        span_id = request.headers.get("x-span-id")
        req_size = _parse_content_length(request.headers.get("content-length"))

        response: Response | None = None
        exc: Exception | None = None
        try:
            response = await call_next(request)
            return response
        except Exception as err:  # noqa: BLE001
            exc = err
            raise
        finally:
            duration_ms = (perf_counter() - started) * 1000.0
            status = response.status_code if response is not None else 500
            res_size = _parse_content_length(response.headers.get("content-length")) if response else None
            route = request.scope.get("route")
            route_path = str(getattr(route, "path", request.url.path))
            event = ApiTelemetryEvent(
                timestamp=datetime.now(UTC).isoformat(),
                level="error" if exc is not None else "info",
                message="api.request",
                trace_id=trace_id,
                span_id=span_id,
                request_id=request_id,
                component="api.route",
                method=request.method,
                route=route_path,
                status=status,
                duration_ms=round(duration_ms, 3),
                request_size_bytes=req_size,
                response_size_bytes=res_size,
                error=type(exc).__name__ if exc is not None else None,
            )
            LOGGER.info(json.dumps(asdict(event), separators=(",", ":")))


def _parse_content_length(raw: str | None) -> int | None:
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None
