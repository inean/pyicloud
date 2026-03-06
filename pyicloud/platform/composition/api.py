"""API composition root based on dependency-injector providers."""

from __future__ import annotations

from dependency_injector import containers, providers

from pyicloud.adapters.access import FileAccessControlStore, InMemoryAccessControlStore
from pyicloud.adapters.auth.fake_scenario_auth import FakeAuthScenario, FakeScenarioAuthSessionAdapter
from pyicloud.adapters.operation_suspension import FileSuspendedOperationStore, InMemorySuspendedOperationStore
from pyicloud.adapters.services import build_core_adapter_bundle
from pyicloud.adapters.session import FileApiSessionStore, InMemoryApiSessionStore
from pyicloud.adapters.token import JwtTokenSigner
from pyicloud.application.core_services import CoreServicesApi
from pyicloud.contexts.crosscutting.auth.application.access_control import AccessControlApiService
from pyicloud.contexts.crosscutting.auth.application.api_auth import AuthApiService
from pyicloud.contexts.crosscutting.auth.application.auth_abuse_guard import AuthAbuseGuardService
from pyicloud.contexts.crosscutting.auth.application.auth_session import AuthSessionService
from pyicloud.contexts.crosscutting.auth.application.operation_suspension import OperationSuspensionService
from pyicloud.contexts.crosscutting.observability.adapters import (
    NullObservabilityAdapter,
    OTelObservabilityAdapter,
    ensure_otel_dependencies,
)
from pyicloud.contexts.crosscutting.observability.application import ObservabilityApi
from pyicloud.platform.composition.settings import ApiAuthSettings, ApiCompositionSettings, AuthScenario
from pyicloud.platform.storage import FileSessionStoreAdapter
from pyicloud.ports import AccessControlQueryPort

_DEFAULT_AUTH_SCENARIOS: dict[str, AuthScenario] = {
    "success@example.com": "success",
    "requires2fa@example.com": "requires_2fa",
    "invalid@example.com": "invalid_credentials",
    "expired@example.com": "expired_session",
}


def _resolve_scenario(username: str, *, settings: ApiAuthSettings) -> FakeAuthScenario:
    normalized_username = str(username).strip().lower()
    if normalized_username in settings.scenario_overrides:
        return settings.scenario_overrides[normalized_username]
    if normalized_username in _DEFAULT_AUTH_SCENARIOS:
        return _DEFAULT_AUTH_SCENARIOS[normalized_username]
    return settings.default_scenario


def build_auth_api_service(
    *,
    settings: ApiCompositionSettings,
    access_query: AccessControlQueryPort | None = None,
) -> AuthApiService:
    """Build the auth service for HTTP API runtime."""
    signer = JwtTokenSigner(
        secret=settings.auth.jwt_secret,
        leeway_seconds=settings.auth.jwt_leeway_seconds,
        enforce_strong_secret=settings.runtime.is_non_dev,
    )
    if settings.auth.session_backend == "memory":
        session_store = InMemoryApiSessionStore()
    else:
        session_store = FileApiSessionStore(root_dir=settings.auth.session_store_dir)

    def auth_service_factory(username: str, password: str):  # noqa: ARG001
        scenario = _resolve_scenario(username, settings=settings.auth)
        auth_adapter = FakeScenarioAuthSessionAdapter(scenario=scenario)
        store_adapter = FileSessionStoreAdapter(root_dir=settings.auth.payload_store_dir)
        return AuthSessionService(auth=auth_adapter, store=store_adapter)

    return AuthApiService(
        token_signer=signer,
        session_query=session_store,
        session_command=session_store,
        auth_service_factory=auth_service_factory,
        access_query=access_query,
        enforce_allowlist=settings.runtime.is_non_dev,
    )


def build_access_control_api_service(*, settings: ApiCompositionSettings) -> AccessControlApiService:
    """Build allowlist/admin access-control service for API runtime."""
    if settings.access_control.backend == "memory":
        store = InMemoryAccessControlStore()
    else:
        store = FileAccessControlStore(root_dir=settings.access_control.store_dir)
    service = AccessControlApiService(query=store, command=store)
    service.ensure_bootstrap_admin(
        strict_mode=settings.runtime.is_non_dev,
        bootstrap_username=settings.access_control.bootstrap_admin,
    )
    return service


def build_operation_suspension_service(*, settings: ApiCompositionSettings) -> OperationSuspensionService:
    """Build suspended-operation service."""
    if settings.operation_suspension.backend == "memory":
        store = InMemorySuspendedOperationStore()
    else:
        store = FileSuspendedOperationStore(root_dir=settings.operation_suspension.store_dir)
    return OperationSuspensionService(
        query=store,
        command=store,
        ttl_seconds=settings.operation_suspension.ttl_seconds,
        max_pending_per_user=settings.operation_suspension.max_pending_per_user,
        max_pending_global=settings.operation_suspension.max_pending_global,
        max_payload_bytes=settings.operation_suspension.max_payload_bytes,
    )


def build_auth_abuse_guard_service(*, settings: ApiCompositionSettings) -> AuthAbuseGuardService:
    """Build auth abuse-guard service."""
    return AuthAbuseGuardService(
        window_seconds=settings.auth_abuse_guard.window_seconds,
        lockout_seconds=settings.auth_abuse_guard.lockout_seconds,
        max_attempts_per_account=settings.auth_abuse_guard.max_attempts_per_account,
        max_attempts_per_ip=settings.auth_abuse_guard.max_attempts_per_ip,
        max_attempts_per_session=settings.auth_abuse_guard.max_attempts_per_session,
    )


def build_core_services_api() -> CoreServicesApi:
    """Build core-services API facade."""
    adapters = build_core_adapter_bundle()
    return CoreServicesApi(
        devices=adapters.devices,
        accounts=adapters.accounts,
        drive=adapters.drive,
        calendars=adapters.calendars,
        contacts=adapters.contacts,
        reminders=adapters.reminders,
        photos=adapters.photos,
        ubiquity=adapters.ubiquity,
    )


def build_observability_api_service(*, settings: ApiCompositionSettings) -> ObservabilityApi:
    """Build observability query service."""
    if settings.observability.adapter == "null":
        adapter = NullObservabilityAdapter()
        return ObservabilityApi(promql=adapter, traceql=adapter, logql=adapter)
    ensure_otel_dependencies()
    adapter = OTelObservabilityAdapter(
        promql_endpoint=settings.observability.promql_endpoint,
        traceql_endpoint=settings.observability.traceql_endpoint,
        logql_endpoint=settings.observability.logql_endpoint,
        timeout_seconds=settings.observability.timeout_seconds,
    )
    return ObservabilityApi(promql=adapter, traceql=adapter, logql=adapter)


def _extract_access_query(service: AccessControlApiService) -> AccessControlQueryPort:
    return service.query_port


class ApiContainer(containers.DeclarativeContainer):
    """Dependency-injector container for API entrypoint composition."""

    settings = providers.Singleton(ApiCompositionSettings.from_env)
    access_control_service = providers.Singleton(build_access_control_api_service, settings=settings)
    access_control_query = providers.Callable(_extract_access_query, service=access_control_service)
    auth_service = providers.Singleton(
        build_auth_api_service,
        settings=settings,
        access_query=access_control_query,
    )
    operation_suspension_service = providers.Singleton(build_operation_suspension_service, settings=settings)
    auth_abuse_guard_service = providers.Singleton(build_auth_abuse_guard_service, settings=settings)
    core_services = providers.Singleton(build_core_services_api)
    observability_service = providers.Singleton(build_observability_api_service, settings=settings)


def build_default_api_container(*, settings: ApiCompositionSettings | None = None) -> ApiContainer:
    """Build the default API DI container."""
    container = ApiContainer()
    if settings is not None:
        container.settings.override(providers.Object(settings))
    return container


__all__ = [
    "ApiCompositionSettings",
    "ApiContainer",
    "build_access_control_api_service",
    "build_auth_abuse_guard_service",
    "build_auth_api_service",
    "build_core_services_api",
    "build_default_api_container",
    "build_observability_api_service",
    "build_operation_suspension_service",
]
