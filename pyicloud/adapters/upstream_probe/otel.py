"""Compatibility shim for telemetry upstream probe OTel adapter."""

from pyicloud.contexts.crosscutting.telemetry.adapters.upstream_probe.otel import (
    OTEL_UPSTREAM_DEPENDENCY_ERROR,
    OTelUpstreamTrafficProbeAdapter,
    ensure_otel_upstream_dependencies,
)

__all__ = ["OTelUpstreamTrafficProbeAdapter", "ensure_otel_upstream_dependencies", "OTEL_UPSTREAM_DEPENDENCY_ERROR"]
