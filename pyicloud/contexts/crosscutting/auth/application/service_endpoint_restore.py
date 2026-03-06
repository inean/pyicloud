"""Application service for runtime endpoint restoration from stored auth payloads."""

from __future__ import annotations

from typing import Any

from pyicloud.ports import ServiceEndpointPort, SessionStorePort


class ServiceEndpointRestoreService:
    """Restore runtime service endpoints through storage and endpoint-factory ports."""

    def __init__(self, *, store: SessionStorePort, endpoint_factory: ServiceEndpointPort):
        self._store = store
        self._endpoint_factory = endpoint_factory

    def restore(self, *, account_id: str, password: str) -> Any | None:
        """Restore a service endpoint for an account if persisted payload is available."""
        payload = self._store.load(account_id)
        if payload is None:
            return None
        return self._endpoint_factory.from_payload(
            username=account_id,
            password=password,
            payload=payload,
        )
