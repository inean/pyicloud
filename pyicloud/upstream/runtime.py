"""Compatibility shim for upstream telemetry runtime bridge."""

from pyicloud.platform.telemetry.upstream.runtime import get_upstream_probe, upstream_capture_body_max_bytes

__all__ = ["get_upstream_probe", "upstream_capture_body_max_bytes"]
