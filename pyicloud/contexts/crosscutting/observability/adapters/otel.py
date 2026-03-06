"""Compatibility bridge to the existing OTel observability adapter implementation."""

from pyicloud.adapters.observability.otel import OTelObservabilityAdapter, ensure_otel_dependencies

__all__ = ["OTelObservabilityAdapter", "ensure_otel_dependencies"]
