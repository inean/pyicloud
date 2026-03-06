"""Runtime bridge for upstream probe adapters."""

from __future__ import annotations

from pyicloud.ports import UpstreamTrafficProbePort


def get_upstream_probe() -> UpstreamTrafficProbePort:
    """
    Resolve the configured upstream probe adapter.

    The implementation lives in adapters; this bridge keeps transport-facing
    modules decoupled from direct adapter imports.
    """

    from pyicloud.contexts.crosscutting.telemetry.adapters.upstream_probe import get_upstream_probe as resolve_probe

    return resolve_probe()


def upstream_capture_body_max_bytes() -> int:
    """
    Resolve max payload bytes captured in upstream probe events.

    The implementation lives in adapters; this bridge keeps transport-facing
    modules decoupled from direct adapter imports.
    """

    from pyicloud.contexts.crosscutting.telemetry.adapters.upstream_probe import (
        upstream_capture_body_max_bytes as resolve_max_bytes,
    )

    return resolve_max_bytes()


__all__ = [
    "get_upstream_probe",
    "upstream_capture_body_max_bytes",
]
