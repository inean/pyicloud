"""Compatibility shims for observability query-side adapters."""

from pyicloud.contexts.crosscutting.observability.adapters import (
    NullObservabilityAdapter,
    OTelObservabilityAdapter,
    ensure_otel_dependencies,
)

__all__ = ["NullObservabilityAdapter", "OTelObservabilityAdapter", "ensure_otel_dependencies"]
