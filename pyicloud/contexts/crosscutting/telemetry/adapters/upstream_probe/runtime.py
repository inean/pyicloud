"""Runtime configuration for upstream traffic probe adapter selection."""

from __future__ import annotations

import os
from functools import lru_cache

from pyicloud.contexts.crosscutting.telemetry.contracts.upstream_probe import UpstreamTrafficProbePort

from .null import NullUpstreamTrafficProbeAdapter
from .otel import OTelUpstreamTrafficProbeAdapter, ensure_otel_upstream_dependencies


def _as_bool(value: str | None, *, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def upstream_capture_enabled() -> bool:
    """Return whether upstream capture is enabled."""
    return _as_bool(os.getenv("PYICLOUD_UPSTREAM_CAPTURE_ENABLED"), default=False)


def upstream_capture_body_max_bytes() -> int:
    """Return max body bytes captured per request/response event."""
    raw = os.getenv("PYICLOUD_UPSTREAM_CAPTURE_BODY_MAX_BYTES", "16384")
    try:
        value = int(raw)
    except ValueError as err:
        raise RuntimeError("PYICLOUD_UPSTREAM_CAPTURE_BODY_MAX_BYTES must be an integer") from err
    return max(256, value)


def validate_upstream_probe_configuration() -> None:
    """Validate runtime guardrails before enabling traffic capture."""
    if not upstream_capture_enabled():
        return

    raw_allowed = os.getenv("PYICLOUD_UPSTREAM_ALLOWED_ENVS", "dev,qa")
    allowed = {item.strip().lower() for item in raw_allowed.split(",") if item.strip()}

    runtime_env = os.getenv("PYICLOUD_API_ENV", os.getenv("PYICLOUD_ENV", "dev")).strip().lower()
    if runtime_env not in allowed:
        raise RuntimeError(
            f"Upstream traffic capture is enabled but runtime environment '{runtime_env}' is not allowed. "
            "Adjust PYICLOUD_UPSTREAM_ALLOWED_ENVS or disable capture."
        )


@lru_cache(maxsize=1)
def get_upstream_probe() -> UpstreamTrafficProbePort:
    """Return the configured upstream traffic probe adapter."""
    if not upstream_capture_enabled():
        return NullUpstreamTrafficProbeAdapter()

    validate_upstream_probe_configuration()

    adapter_name = os.getenv("PYICLOUD_UPSTREAM_PROBE_ADAPTER", "null").strip().lower()
    if adapter_name == "null":
        return NullUpstreamTrafficProbeAdapter()
    if adapter_name == "otel":
        ensure_otel_upstream_dependencies()
        return OTelUpstreamTrafficProbeAdapter()
    raise RuntimeError(f"Unsupported upstream probe adapter: {adapter_name}")


def reset_upstream_probe_cache() -> None:
    """Reset adapter cache, mostly used by tests when env vars change."""
    get_upstream_probe.cache_clear()


__all__ = [
    "get_upstream_probe",
    "reset_upstream_probe_cache",
    "upstream_capture_body_max_bytes",
    "upstream_capture_enabled",
    "validate_upstream_probe_configuration",
]
