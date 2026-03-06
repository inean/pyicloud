"""Compatibility shim for telemetry upstream probe runtime selection."""

from pyicloud.contexts.crosscutting.telemetry.adapters.upstream_probe.runtime import (
    get_upstream_probe,
    reset_upstream_probe_cache,
    upstream_capture_body_max_bytes,
    upstream_capture_enabled,
    validate_upstream_probe_configuration,
)

__all__ = [
    "get_upstream_probe",
    "reset_upstream_probe_cache",
    "upstream_capture_body_max_bytes",
    "upstream_capture_enabled",
    "validate_upstream_probe_configuration",
]
