"""FastAPI application factory for the pyicloud API layer."""

from __future__ import annotations

from fastapi import FastAPI

from pyicloud.adapters.upstream_probe import validate_upstream_probe_configuration
from pyicloud.application.access_control import AccessControlApiService
from pyicloud.application.api_auth import AuthApiService
from pyicloud.application.auth_abuse_guard import AuthAbuseGuardService
from pyicloud.application.core_services import CoreServicesApi
from pyicloud.application.observability import ObservabilityApi
from pyicloud.application.operation_suspension import OperationSuspensionService
from pyicloud.bootstrap import (
    build_default_access_control_api,
    build_default_auth_abuse_guard_service,
    build_default_auth_api_service,
    build_default_core_services_api,
    build_default_observability_api,
    build_default_operation_suspension_service,
)

from .errors import register_exception_handlers
from .instrumentation import ApiTelemetryMiddleware, telemetry_enabled
from .routers import (
    account_router,
    admin_router,
    auth_router,
    calendar_router,
    contacts_router,
    devices_router,
    drive_router,
    observability_router,
    photos_router,
    reminders_router,
    ubiquity_router,
)


def _build_default_auth_service(
    *,
    access_control_service: AccessControlApiService | None = None,
) -> AuthApiService:
    access_query = access_control_service.query_port if access_control_service is not None else None
    return build_default_auth_api_service(access_query=access_query)


def _build_default_access_control_service() -> AccessControlApiService:
    return build_default_access_control_api()


def _build_default_core_services() -> CoreServicesApi:
    return build_default_core_services_api()


def _build_default_observability_service() -> ObservabilityApi:
    return build_default_observability_api()


def _build_default_operation_suspension() -> OperationSuspensionService:
    return build_default_operation_suspension_service()


def _build_default_auth_abuse_guard() -> AuthAbuseGuardService:
    return build_default_auth_abuse_guard_service()


def create_app(
    *,
    auth_service: AuthApiService | None = None,
    access_control_service: AccessControlApiService | None = None,
    operation_suspension_service: OperationSuspensionService | None = None,
    auth_abuse_guard_service: AuthAbuseGuardService | None = None,
    core_services: CoreServicesApi | None = None,
    observability_service: ObservabilityApi | None = None,
) -> FastAPI:
    """Build and configure the FastAPI application."""
    validate_upstream_probe_configuration()

    app = FastAPI(title="pyicloud API", version="1.0.0")
    if telemetry_enabled():
        app.add_middleware(ApiTelemetryMiddleware)
    resolved_access_control = access_control_service or _build_default_access_control_service()
    app.state.access_control_service = resolved_access_control
    app.state.auth_service = auth_service or _build_default_auth_service(access_control_service=resolved_access_control)
    app.state.operation_suspension_service = operation_suspension_service or _build_default_operation_suspension()
    app.state.auth_abuse_guard_service = auth_abuse_guard_service or _build_default_auth_abuse_guard()
    app.state.core_services = core_services or _build_default_core_services()
    app.state.observability_service = observability_service or _build_default_observability_service()
    register_exception_handlers(app)

    app.include_router(auth_router)
    app.include_router(admin_router)
    app.include_router(devices_router)
    app.include_router(account_router)
    app.include_router(calendar_router)
    app.include_router(contacts_router)
    app.include_router(drive_router)
    app.include_router(reminders_router)
    app.include_router(photos_router)
    app.include_router(ubiquity_router)
    app.include_router(observability_router)

    @app.get("/healthz")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


__all__ = ["create_app"]
