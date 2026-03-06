"""Bootstrap utilities for composing application services."""

from __future__ import annotations

from typing import Any

from .api_runtime import (
    build_default_access_control_api,
    build_default_auth_abuse_guard_service,
    build_default_auth_api_service,
    build_default_core_services_api,
    build_default_observability_api,
    build_default_operation_suspension_service,
)
from .session_endpoint_restore import build_service_endpoint_restore


def build_auth_session_service(*args: Any, **kwargs: Any) -> Any:
    """Lazy shim for legacy tree-backed auth-session bootstrap."""
    from .auth_session import build_auth_session_service as _build_auth_session_service

    return _build_auth_session_service(*args, **kwargs)


__all__ = [
    "build_auth_session_service",
    "build_default_access_control_api",
    "build_default_auth_abuse_guard_service",
    "build_service_endpoint_restore",
    "build_default_auth_api_service",
    "build_default_core_services_api",
    "build_default_observability_api",
    "build_default_operation_suspension_service",
]
