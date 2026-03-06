from __future__ import annotations

from types import SimpleNamespace

from dependency_injector import providers

import pyicloud.interfaces.api.app as api_app
from pyicloud.platform.composition.api import build_default_api_container
from pyicloud.platform.composition.settings import (
    AccessControlSettings,
    ApiAuthSettings,
    ApiCompositionSettings,
    ApiRuntimeSettings,
    AuthAbuseGuardSettings,
    ObservabilitySettings,
    OperationSuspensionSettings,
)


def _dev_settings() -> ApiCompositionSettings:
    return ApiCompositionSettings(
        runtime=ApiRuntimeSettings(runtime_env="dev"),
        auth=ApiAuthSettings(),
        access_control=AccessControlSettings(),
        operation_suspension=OperationSuspensionSettings(),
        auth_abuse_guard=AuthAbuseGuardSettings(),
        observability=ObservabilitySettings(),
    )


def test_create_app_resolves_defaults_from_container() -> None:
    container = build_default_api_container(settings=_dev_settings())
    fake_access = SimpleNamespace(query_port=object())
    fake_auth = object()
    fake_operation = object()
    fake_guard = object()
    fake_core = object()
    fake_observability = object()

    with container.access_control_service.override(providers.Object(fake_access)):
        with container.auth_service.override(providers.Object(fake_auth)):
            with container.operation_suspension_service.override(providers.Object(fake_operation)):
                with container.auth_abuse_guard_service.override(providers.Object(fake_guard)):
                    with container.core_services.override(providers.Object(fake_core)):
                        with container.observability_service.override(providers.Object(fake_observability)):
                            app = api_app.create_app(container=container)

    assert app.state.container is container
    assert app.state.access_control_service is fake_access
    assert app.state.auth_service is fake_auth
    assert app.state.operation_suspension_service is fake_operation
    assert app.state.auth_abuse_guard_service is fake_guard
    assert app.state.core_services is fake_core
    assert app.state.observability_service is fake_observability


def test_create_app_explicit_services_override_container_defaults() -> None:
    container = build_default_api_container(settings=_dev_settings())
    explicit_access = SimpleNamespace(query_port=object())
    explicit_auth = object()
    explicit_operation = object()
    explicit_guard = object()
    explicit_core = object()
    explicit_observability = object()

    app = api_app.create_app(
        container=container,
        auth_service=explicit_auth,  # type: ignore[arg-type]
        access_control_service=explicit_access,  # type: ignore[arg-type]
        operation_suspension_service=explicit_operation,  # type: ignore[arg-type]
        auth_abuse_guard_service=explicit_guard,  # type: ignore[arg-type]
        core_services=explicit_core,  # type: ignore[arg-type]
        observability_service=explicit_observability,  # type: ignore[arg-type]
    )

    assert app.state.container is container
    assert app.state.access_control_service is explicit_access
    assert app.state.auth_service is explicit_auth
    assert app.state.operation_suspension_service is explicit_operation
    assert app.state.auth_abuse_guard_service is explicit_guard
    assert app.state.core_services is explicit_core
    assert app.state.observability_service is explicit_observability


def test_create_app_rebuilds_auth_service_with_explicit_access_query(monkeypatch) -> None:
    settings = _dev_settings()
    container = build_default_api_container(settings=settings)
    explicit_access = SimpleNamespace(query_port=object())
    fake_auth = object()
    captured: dict[str, object] = {}

    def _fake_build_auth_api_service(*, settings, access_query=None):  # noqa: ANN001,ANN202
        captured["settings"] = settings
        captured["access_query"] = access_query
        return fake_auth

    monkeypatch.setattr(api_app, "build_auth_api_service", _fake_build_auth_api_service)

    app = api_app.create_app(
        container=container,
        access_control_service=explicit_access,  # type: ignore[arg-type]
    )

    assert app.state.auth_service is fake_auth
    assert captured["settings"] is settings
    assert captured["access_query"] is explicit_access.query_port


def test_api_container_critical_providers_are_singletons() -> None:
    container = build_default_api_container(settings=_dev_settings())
    assert container.settings() is container.settings()
    assert container.access_control_service() is container.access_control_service()
    assert container.auth_service() is container.auth_service()
    assert container.operation_suspension_service() is container.operation_suspension_service()
    assert container.auth_abuse_guard_service() is container.auth_abuse_guard_service()
    assert container.observability_service() is container.observability_service()
