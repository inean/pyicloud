"""Compatibility shim for upstream payload redaction helpers."""

from pyicloud.platform.telemetry.upstream.sanitize import sanitize_body, sanitize_headers

__all__ = ["sanitize_body", "sanitize_headers"]
