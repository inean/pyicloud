"""Legacy-backed adapter for drive domain operations."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pyicloud.ports import DriveServicePort

from .runtime import LegacyServicesAdapterBase, LegacyServicesRuntime, NamedBytesIO


class DriveServiceAdapter(LegacyServicesAdapterBase, DriveServicePort):
    """Map iCloud Drive operations to the drive service port contract."""

    def _resolve_drive_node(self, *, username: str, path: str):
        drive_root = self._services(username=username).drive
        return LegacyServicesRuntime.resolve_path(root=drive_root, path=path)

    @staticmethod
    def _node_metadata(path: str, node: Any) -> dict[str, Any]:
        return {
            "path": path or "/",
            "name": node.name,
            "type": node.type,
            "size": node.size,
            "date_changed": str(node.date_changed) if getattr(node, "date_changed", None) else None,
            "date_modified": str(node.date_modified) if getattr(node, "date_modified", None) else None,
            "date_last_open": str(node.date_last_open) if getattr(node, "date_last_open", None) else None,
        }

    def tree(self, *, username: str, path: str) -> Mapping[str, Any]:
        node = self._resolve_drive_node(username=username, path=path)
        data = self._node_metadata(path=path or "/", node=node)
        data["children"] = node.dir()
        return data

    def file_metadata(self, *, username: str, path: str) -> Mapping[str, Any]:
        return self._node_metadata(path=path, node=self._resolve_drive_node(username=username, path=path))

    def file_content(self, *, username: str, path: str) -> bytes:
        node = self._resolve_drive_node(username=username, path=path)
        with node.open(stream=True) as response:
            return LegacyServicesRuntime.stream_bytes(response)

    def create_folder(self, *, username: str, parent_path: str, name: str) -> None:
        parent = self._resolve_drive_node(username=username, path=parent_path)
        parent.mkdir(name)

    def upload_file(self, *, username: str, parent_path: str, filename: str, content: bytes) -> None:
        parent = self._resolve_drive_node(username=username, path=parent_path)
        fileobj = NamedBytesIO(content, name=filename)
        parent.upload(fileobj)

    def rename_node(self, *, username: str, path: str, new_name: str) -> None:
        self._resolve_drive_node(username=username, path=path).rename(new_name)

    def delete_node(self, *, username: str, path: str) -> None:
        self._resolve_drive_node(username=username, path=path).delete()
