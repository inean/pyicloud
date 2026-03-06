"""Compatibility shims for telemetry upstream probe adapters."""

from pyicloud.contexts.crosscutting.telemetry.adapters.upstream_probe import (
    NullUpstreamTrafficProbeAdapter,
    OTelUpstreamTrafficProbeAdapter,
    ensure_otel_upstream_dependencies,
    get_upstream_probe,
    reset_upstream_probe_cache,
    upstream_capture_body_max_bytes,
    upstream_capture_enabled,
    validate_upstream_probe_configuration,
)

__all__ = [
    "NullUpstreamTrafficProbeAdapter",
    "OTelUpstreamTrafficProbeAdapter",
    "ensure_otel_upstream_dependencies",
    "get_upstream_probe",
    "reset_upstream_probe_cache",
    "upstream_capture_body_max_bytes",
    "upstream_capture_enabled",
    "validate_upstream_probe_configuration",
]
