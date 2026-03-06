"""Legacy-backed adapter for drive domain operations."""

from __future__ import annotations

from pyicloud.domain import DriveNodeDTO
from pyicloud.ports import DriveServicePort

from .clients.drive import DriveClient, LegacyDriveClient
from .mappers.drive import map_drive_node
from .runtime import LegacyServicesAdapterBase


class DriveServiceAdapter(LegacyServicesAdapterBase, DriveServicePort):
    """Map iCloud Drive operations to the drive service port contract."""

    def _drive_client(self, *, username: str) -> DriveClient:
        return LegacyDriveClient(runtime=self._runtime, username=username)

    async def tree(self, *, username: str, path: str) -> DriveNodeDTO:
        node = await self._run_blocking(lambda: self._drive_client(username=username).tree(path=path))
        return map_drive_node(node)

    async def file_metadata(self, *, username: str, path: str) -> DriveNodeDTO:
        node = await self._run_blocking(lambda: self._drive_client(username=username).metadata(path=path))
        return map_drive_node(node)

    async def file_content(self, *, username: str, path: str) -> bytes:
        return await self._run_blocking(lambda: self._drive_client(username=username).content(path=path))

    async def create_folder(self, *, username: str, parent_path: str, name: str) -> None:
        await self._run_blocking(
            lambda: self._drive_client(username=username).create_folder(parent_path=parent_path, name=name)
        )

    async def upload_file(self, *, username: str, parent_path: str, filename: str, content: bytes) -> None:
        await self._run_blocking(
            lambda: self._drive_client(username=username).upload_file(
                parent_path=parent_path,
                filename=filename,
                content=content,
            )
        )

    async def rename_node(self, *, username: str, path: str, new_name: str) -> None:
        await self._run_blocking(
            lambda: self._drive_client(username=username).rename_node(path=path, new_name=new_name)
        )

    async def delete_node(self, *, username: str, path: str) -> None:
        await self._run_blocking(lambda: self._drive_client(username=username).delete_node(path=path))
