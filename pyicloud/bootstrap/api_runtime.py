"""Compatibility bootstrap shim backed by platform composition containers."""

from __future__ import annotations

from pyicloud.application.core_services import CoreServicesApi
from pyicloud.contexts.crosscutting.auth.application.access_control import AccessControlApiService
from pyicloud.contexts.crosscutting.auth.application.api_auth import AuthApiService
from pyicloud.contexts.crosscutting.auth.application.auth_abuse_guard import AuthAbuseGuardService
from pyicloud.contexts.crosscutting.auth.application.operation_suspension import OperationSuspensionService
from pyicloud.contexts.crosscutting.observability.adapters import (
    NullObservabilityAdapter,
    OTelObservabilityAdapter,
    ensure_otel_dependencies,
)
from pyicloud.contexts.crosscutting.observability.application import ObservabilityApi
from pyicloud.platform.composition.api import (
    ApiCompositionSettings,
    build_access_control_api_service,
    build_auth_abuse_guard_service,
    build_auth_api_service,
    build_core_services_api,
    build_observability_api_service,
    build_operation_suspension_service,
)
from pyicloud.platform.storage import FileSessionStoreAdapter
from pyicloud.ports import AccessControlQueryPort


def build_default_auth_api_service(*, access_query: AccessControlQueryPort | None = None) -> AuthApiService:
    """Compose the default auth service used by the HTTP API runtime."""
    return build_auth_api_service(settings=ApiCompositionSettings.from_env(), access_query=access_query)


def build_default_access_control_api() -> AccessControlApiService:
    """Compose default allowlist/admin access-control service for API runtime."""
    return build_access_control_api_service(settings=ApiCompositionSettings.from_env())


def build_default_operation_suspension_service() -> OperationSuspensionService:
    """Compose default suspended-operation service for challenge-driven operation resume."""
    return build_operation_suspension_service(settings=ApiCompositionSettings.from_env())


def build_default_auth_abuse_guard_service() -> AuthAbuseGuardService:
    """Compose auth abuse guard service (rate-limit + lockout) for challenge flows."""
    return build_auth_abuse_guard_service(settings=ApiCompositionSettings.from_env())


def build_default_core_services_api() -> CoreServicesApi:
    """Compose the default core-services application facade for API routes."""
    return build_core_services_api()


def build_default_observability_api() -> ObservabilityApi:
    """Compose the default observability application facade."""
    return build_observability_api_service(settings=ApiCompositionSettings.from_env())


__all__ = [
    "AccessControlApiService",
    "AuthAbuseGuardService",
    "AuthApiService",
    "CoreServicesApi",
    "FileSessionStoreAdapter",
    "NullObservabilityAdapter",
    "OTelObservabilityAdapter",
    "ObservabilityApi",
    "OperationSuspensionService",
    "build_default_access_control_api",
    "build_default_auth_abuse_guard_service",
    "build_default_auth_api_service",
    "build_default_core_services_api",
    "build_default_observability_api",
    "build_default_operation_suspension_service",
    "ensure_otel_dependencies",
]
