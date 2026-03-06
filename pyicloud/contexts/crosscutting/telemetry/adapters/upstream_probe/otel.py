"""Compatibility bridge to the existing OTel upstream probe implementation."""

from pyicloud.adapters.upstream_probe.otel import OTelUpstreamTrafficProbeAdapter, ensure_otel_upstream_dependencies

__all__ = ["OTelUpstreamTrafficProbeAdapter", "ensure_otel_upstream_dependencies"]
