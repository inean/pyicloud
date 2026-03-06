"""Compatibility shim for observability OTel adapter."""

from pyicloud.contexts.crosscutting.observability.adapters.otel import (
    OTEL_DEPENDENCY_ERROR,
    OTelObservabilityAdapter,
    ensure_otel_dependencies,
)

__all__ = ["OTelObservabilityAdapter", "OTEL_DEPENDENCY_ERROR", "ensure_otel_dependencies"]
