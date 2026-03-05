"""Endpoint restoration helpers used by the compatibility `PyiCloudService` facade."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from pyicloud.adapters.session_endpoint import LegacyServiceEndpointFactoryAdapter
from pyicloud.adapters.store import FileSessionStoreAdapter
from pyicloud.ports import ServiceEndpointPort, SessionStorePort


def restore_legacy_endpoint_from_store(
    *,
    username: str,
    password: str,
    store: SessionStorePort | None = None,
    endpoint_factory: ServiceEndpointPort | None = None,
) -> Any | None:
    """Restore a runtime service endpoint directly from persisted session payload data."""
    session_store = store or FileSessionStoreAdapter()
    service_endpoint_factory = endpoint_factory or LegacyServiceEndpointFactoryAdapter()

    payload = session_store.load(username)
    if payload is None:
        return None

    return service_endpoint_factory.from_payload(
        username=username,
        password=password,
        payload=payload,
    )


async def authenticate_legacy_endpoint(
    *,
    username: str,
    password: str,
    interactive: bool,
    auth_runner: Callable[..., Any] | None = None,
    restore_builder: Callable[..., Any] | None = None,
    store: SessionStorePort | None = None,
    endpoint_factory: ServiceEndpointPort | None = None,
) -> Any:
    """Authenticate and return a services endpoint using the bootstrap flow."""
    if auth_runner is None:
        from pyicloud.cli_auth import run_bootstrap_auth

        auth_runner = run_bootstrap_auth

    await auth_runner(
        username=username,
        password=password,
        interactive=interactive,
    )

    if restore_builder is not None:
        restore = restore_builder()
        endpoint = restore.restore(
            account_id=username,
            password=password,
        )
    else:
        endpoint = restore_legacy_endpoint_from_store(
            username=username,
            password=password,
            store=store,
            endpoint_factory=endpoint_factory,
        )
    if endpoint is None:
        raise RuntimeError(f"Authenticated but no endpoint payload found for {username}")
    return endpoint
