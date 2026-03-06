"""Shared runtime support for legacy-backed provider adapters."""

from __future__ import annotations

import asyncio
import io
from collections.abc import Callable
from typing import Any

from pyicloud.adapters.services.provider_sync import PyiCloudServices
from pyicloud.adapters.session_endpoint import LegacyServiceEndpointFactoryAdapter
from pyicloud.platform.storage import FileSessionStoreAdapter
from pyicloud.platform.telemetry.upstream import ensure_upstream_context
from pyicloud.ports import ServiceEndpointPort, SessionStorePort


class NamedBytesIO(io.BytesIO):
    """Bytes buffer with a stable ``name`` attribute for legacy upload APIs."""

    def __init__(self, data: bytes, name: str):
        super().__init__(data)
        self.name = name


class ServiceRuntime:
    """Build ``PyiCloudServices`` instances from persisted endpoint payloads."""

    def __init__(
        self,
        *,
        session_store: SessionStorePort | None = None,
        endpoint_factory: ServiceEndpointPort | None = None,
    ):
        self._store = session_store or FileSessionStoreAdapter()
        self._endpoint_factory = endpoint_factory or LegacyServiceEndpointFactoryAdapter()

    def services(self, *, username: str) -> PyiCloudServices:
        payload = self._store.load(username)
        if payload is None:
            raise RuntimeError(f"No stored endpoint payload found for account: {username}")
        ensure_upstream_context(
            username=username,
            flow_id=str(payload.get("__flow_id", "")).strip() or None,
        )
        endpoint = self._endpoint_factory.from_payload(
            username=username,
            password="",
            payload=payload,
        )
        if endpoint is None:
            raise RuntimeError(f"No stored endpoint payload found for account: {username}")
        return PyiCloudServices(endpoint=endpoint)

    @staticmethod
    def resolve_path(*, root: Any, path: str) -> Any:
        node = root
        clean_path = path.strip()
        if not clean_path or clean_path == "/":
            return node
        for part in [segment for segment in clean_path.strip("/").split("/") if segment]:
            node = node[part]
        return node

    @staticmethod
    def stream_bytes(response: Any) -> bytes:
        chunks: list[bytes] = []
        with response:
            for chunk in response.iter_raw():
                if isinstance(chunk, bytes):
                    chunks.append(chunk)
                else:
                    chunks.append(bytes(chunk))
        return b"".join(chunks)


class ServicesAdapterBase:
    """Base adapter with shared access to legacy runtime composition."""

    def __init__(self, *, runtime: ServiceRuntime):
        self._runtime = runtime

    @staticmethod
    async def _run_blocking[T](call: Callable[[], T]) -> T:
        """Execute blocking provider-runtime operations off the event loop."""
        return await asyncio.to_thread(call)

    def _services(self, *, username: str) -> PyiCloudServices:
        return self._runtime.services(username=username)
