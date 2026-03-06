"""Bootstrap helpers for composing default API-facing application services."""

from __future__ import annotations

import os
from typing import Any

from pyicloud.adapters.access import FileAccessControlStore, InMemoryAccessControlStore
from pyicloud.adapters.observability import NullObservabilityAdapter, OTelObservabilityAdapter, ensure_otel_dependencies
from pyicloud.adapters.services import build_core_adapter_bundle
from pyicloud.adapters.session import FileApiSessionStore, InMemoryApiSessionStore
from pyicloud.adapters.token import JwtTokenSigner
from pyicloud.application.access_control import AccessControlApiService
from pyicloud.application.api_auth import AuthApiService
from pyicloud.application.core_services import CoreServicesApi
from pyicloud.application.observability import ObservabilityApi
from pyicloud.bootstrap.auth_session import build_auth_session_service
from pyicloud.models.settings import Settings
from pyicloud.ports import AccessControlQueryPort
from pyicloud.trees.setup import SetupHooks


class _ApiSetupHooks(SetupHooks):
    """Non-interactive setup hooks used by API authentication flows."""

    def __init__(self, *, password: str):
        self._password = password

    def get_password(self, username: str) -> str:  # noqa: ARG002
        return self._password

    def get_security_code(self, device: Any = None) -> str:  # noqa: ARG002
        return ""

    def get_trusted_device(self, devices):  # noqa: ANN001, ARG002
        return None


def _runtime_env() -> str:
    return os.getenv("PYICLOUD_API_ENV", os.getenv("PYICLOUD_ENV", "dev")).strip().lower()


def _is_non_dev_runtime(runtime_env: str) -> bool:
    return runtime_env not in {"dev", "development", "local", "test", "testing"}


def build_default_auth_api_service(*, access_query: AccessControlQueryPort | None = None) -> AuthApiService:
    """Compose the default auth service used by the HTTP API runtime."""
    runtime_env = _runtime_env()
    is_non_dev = _is_non_dev_runtime(runtime_env)

    secret = os.getenv("PYICLOUD_API_JWT_SECRET", "pyicloud-api-dev-secret")
    if is_non_dev and "PYICLOUD_API_JWT_SECRET" not in os.environ:
        raise RuntimeError("PYICLOUD_API_JWT_SECRET must be explicitly configured in non-dev runtime")

    leeway_seconds_raw = os.getenv("PYICLOUD_API_JWT_LEEWAY_SECONDS", "0")
    try:
        leeway_seconds = int(leeway_seconds_raw)
    except ValueError as err:
        raise RuntimeError("PYICLOUD_API_JWT_LEEWAY_SECONDS must be an integer") from err

    signer = JwtTokenSigner(
        secret=secret,
        leeway_seconds=leeway_seconds,
        enforce_strong_secret=is_non_dev,
    )

    session_backend = os.getenv("PYICLOUD_API_SESSION_BACKEND", "memory").strip().lower()
    if session_backend in {"memory", "in-memory", "inmemory"}:
        session_store = InMemoryApiSessionStore()
    elif session_backend == "file":
        session_store = FileApiSessionStore(root_dir=os.getenv("PYICLOUD_API_SESSION_STORE_DIR"))
    else:
        raise RuntimeError(f"Unsupported auth session backend: {session_backend}")
    store_dir = os.getenv("PYICLOUD_SESSION_STORE_DIR")

    def auth_service_factory(username: str, password: str):
        settings = Settings.create(username=username, password=password or None)
        hooks = _ApiSetupHooks(password=password)
        return build_auth_session_service(settings=settings, hooks=hooks, store_dir=store_dir)

    return AuthApiService(
        token_signer=signer,
        session_query=session_store,
        session_command=session_store,
        auth_service_factory=auth_service_factory,
        access_query=access_query,
        enforce_allowlist=is_non_dev,
    )


def build_default_access_control_api() -> AccessControlApiService:
    """Compose default allowlist/admin access-control service for API runtime."""
    runtime_env = _runtime_env()
    is_non_dev = _is_non_dev_runtime(runtime_env)

    backend_default = "file" if is_non_dev else "memory"
    backend_name = os.getenv("PYICLOUD_API_ACL_BACKEND", backend_default).strip().lower()
    if backend_name in {"memory", "in-memory", "inmemory"}:
        if is_non_dev:
            raise RuntimeError("PYICLOUD_API_ACL_BACKEND must use file storage in non-dev runtime")
        store = InMemoryAccessControlStore()
    elif backend_name == "file":
        store = FileAccessControlStore(root_dir=os.getenv("PYICLOUD_API_ACL_STORE_DIR"))
    else:
        raise RuntimeError(f"Unsupported access-control backend: {backend_name}")

    service = AccessControlApiService(query=store, command=store)
    service.ensure_bootstrap_admin(
        strict_mode=is_non_dev,
        bootstrap_username=os.getenv("PYICLOUD_API_BOOTSTRAP_ADMIN"),
    )
    return service


def build_default_core_services_api() -> CoreServicesApi:
    """Compose the default core-services application facade for API routes."""
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


def build_default_observability_api() -> ObservabilityApi:
    """Compose the default observability application facade."""
    adapter_name = os.getenv("PYICLOUD_OBSERVABILITY_ADAPTER", "null").strip().lower()
    if adapter_name == "null":
        adapter = NullObservabilityAdapter()
        return ObservabilityApi(promql=adapter, traceql=adapter, logql=adapter)
    if adapter_name == "otel":
        ensure_otel_dependencies()
        timeout_raw = os.getenv("PYICLOUD_OBSERVABILITY_TIMEOUT_SECONDS", "10.0")
        try:
            timeout_seconds = float(timeout_raw)
        except ValueError as err:
            raise RuntimeError("PYICLOUD_OBSERVABILITY_TIMEOUT_SECONDS must be numeric") from err
        adapter = OTelObservabilityAdapter(
            promql_endpoint=os.getenv("PYICLOUD_OBSERVABILITY_PROMQL_ENDPOINT"),
            traceql_endpoint=os.getenv("PYICLOUD_OBSERVABILITY_TRACEQL_ENDPOINT"),
            logql_endpoint=os.getenv("PYICLOUD_OBSERVABILITY_LOGQL_ENDPOINT"),
            timeout_seconds=timeout_seconds,
        )
        return ObservabilityApi(promql=adapter, traceql=adapter, logql=adapter)
    raise RuntimeError(f"Unsupported observability adapter: {adapter_name}")
