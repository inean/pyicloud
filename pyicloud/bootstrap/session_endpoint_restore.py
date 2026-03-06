"""Bootstrap helper for endpoint restoration service composition."""

from __future__ import annotations

from pathlib import Path

from pyicloud.adapters.session_endpoint import LegacyServiceEndpointFactoryAdapter
from pyicloud.application import ServiceEndpointRestoreService
from pyicloud.platform.storage import FileSessionStoreAdapter


def build_service_endpoint_restore(*, store_dir: str | Path | None = None) -> ServiceEndpointRestoreService:
    """Compose endpoint restoration service with file store + legacy endpoint factory adapters."""
    return ServiceEndpointRestoreService(
        store=FileSessionStoreAdapter(root_dir=store_dir),
        endpoint_factory=LegacyServiceEndpointFactoryAdapter(),
    )
