"""Compatibility shim for upstream event builders."""

from pyicloud.platform.telemetry.upstream.events import (
    build_error_event,
    build_request_event,
    build_response_event,
    hydrate_from_context,
    snapshot_context,
)

__all__ = [
    "build_error_event",
    "build_request_event",
    "build_response_event",
    "hydrate_from_context",
    "snapshot_context",
]
