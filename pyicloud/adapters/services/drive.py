"""Legacy-backed adapter for drive domain operations."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pyicloud.ports import DriveServicePort

from .clients.drive import DriveClient, LegacyDriveClient
from .mappers.drive import map_drive_node
from .runtime import LegacyServicesAdapterBase


class DriveServiceAdapter(LegacyServicesAdapterBase, DriveServicePort):
    """Map iCloud Drive operations to the drive service port contract."""

    def _drive_client(self, *, username: str) -> DriveClient:
        return LegacyDriveClient(runtime=self._runtime, username=username)

    def tree(self, *, username: str, path: str) -> Mapping[str, Any]:
        return map_drive_node(self._drive_client(username=username).tree(path=path))

    def file_metadata(self, *, username: str, path: str) -> Mapping[str, Any]:
        return map_drive_node(self._drive_client(username=username).metadata(path=path))

    def file_content(self, *, username: str, path: str) -> bytes:
        return self._drive_client(username=username).content(path=path)

    def create_folder(self, *, username: str, parent_path: str, name: str) -> None:
        self._drive_client(username=username).create_folder(parent_path=parent_path, name=name)

    def upload_file(self, *, username: str, parent_path: str, filename: str, content: bytes) -> None:
        self._drive_client(username=username).upload_file(parent_path=parent_path, filename=filename, content=content)

    def rename_node(self, *, username: str, path: str, new_name: str) -> None:
        self._drive_client(username=username).rename_node(path=path, new_name=new_name)

    def delete_node(self, *, username: str, path: str) -> None:
        self._drive_client(username=username).delete_node(path=path)
