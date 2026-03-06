"""Legacy-backed adapter for ubiquity file library operations."""

from __future__ import annotations

from pyicloud.adapters.services.clients.ubiquity import LegacyUbiquityClient, UbiquityClient
from pyicloud.adapters.services.mappers.ubiquity import map_ubiquity_node
from pyicloud.adapters.services.runtime import ServicesAdapterBase
from pyicloud.contexts.services.contracts.services import UbiquityServicePort
from pyicloud.domain import UbiquityNodeDTO


class UbiquityServiceAdapter(ServicesAdapterBase, UbiquityServicePort):
    """Map ubiquity operations to the ubiquity service port contract."""

    def _ubiquity_client(self, *, username: str) -> UbiquityClient:
        return LegacyUbiquityClient(runtime=self._runtime, username=username)

    async def ubiquity_tree(self, *, username: str, path: str) -> UbiquityNodeDTO:
        node = await self._run_blocking(lambda: self._ubiquity_client(username=username).tree(path=path))
        return map_ubiquity_node(node)

    async def ubiquity_file_metadata(self, *, username: str, path: str) -> UbiquityNodeDTO:
        node = await self._run_blocking(lambda: self._ubiquity_client(username=username).metadata(path=path))
        return map_ubiquity_node(node)

    async def ubiquity_file_content(self, *, username: str, path: str) -> bytes:
        return await self._run_blocking(lambda: self._ubiquity_client(username=username).content(path=path))
