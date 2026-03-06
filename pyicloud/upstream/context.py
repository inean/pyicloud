"""Compatibility shim for upstream context helpers."""

from pyicloud.platform.telemetry.upstream.context import (
    bind_upstream_context,
    current_flow_id,
    current_upstream_context,
    ensure_upstream_context,
    inject_flow_into_payload,
)

__all__ = [
    "bind_upstream_context",
    "current_flow_id",
    "current_upstream_context",
    "ensure_upstream_context",
    "inject_flow_into_payload",
]
