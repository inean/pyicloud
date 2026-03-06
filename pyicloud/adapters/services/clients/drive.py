"""Typed client for legacy iCloud Drive operations."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from pyicloud.adapters.services.runtime import NamedBytesIO, ServiceRuntime


@dataclass(frozen=True)
class DriveNodeView:
    path: str
    name: str
    node_type: str
    size: int | None
    date_changed: str | None
    date_modified: str | None
    date_last_open: str | None
    children: Sequence[dict[str, Any]] | None = None


class DriveClient(Protocol):
    def tree(self, *, path: str) -> DriveNodeView: ...
    def metadata(self, *, path: str) -> DriveNodeView: ...
    def content(self, *, path: str) -> bytes: ...
    def create_folder(self, *, parent_path: str, name: str) -> None: ...
    def upload_file(self, *, parent_path: str, filename: str, content: bytes) -> None: ...
    def rename_node(self, *, path: str, new_name: str) -> None: ...
    def delete_node(self, *, path: str) -> None: ...


class LegacyDriveClient:
    """Query/mutate drive data through legacy drive node APIs with typed views."""

    def __init__(self, *, runtime: ServiceRuntime, username: str):
        self._runtime = runtime
        self._username = username

    def _resolve_drive_node(self, *, path: str):
        drive_root = self._runtime.services(username=self._username).drive
        return ServiceRuntime.resolve_path(root=drive_root, path=path)

    @staticmethod
    def _node_view(*, path: str, node: Any, children: Sequence[dict[str, Any]] | None = None) -> DriveNodeView:
        return DriveNodeView(
            path=path or "/",
            name=str(node.name),
            node_type=str(node.type),
            size=int(node.size) if node.size is not None else None,
            date_changed=str(node.date_changed) if getattr(node, "date_changed", None) else None,
            date_modified=str(node.date_modified) if getattr(node, "date_modified", None) else None,
            date_last_open=str(node.date_last_open) if getattr(node, "date_last_open", None) else None,
            children=children,
        )

    def tree(self, *, path: str) -> DriveNodeView:
        node = self._resolve_drive_node(path=path)
        children = node.dir()
        return self._node_view(path=path or "/", node=node, children=children)

    def metadata(self, *, path: str) -> DriveNodeView:
        node = self._resolve_drive_node(path=path)
        return self._node_view(path=path, node=node)

    def content(self, *, path: str) -> bytes:
        node = self._resolve_drive_node(path=path)
        with node.open(stream=True) as response:
            return ServiceRuntime.stream_bytes(response)

    def create_folder(self, *, parent_path: str, name: str) -> None:
        parent = self._resolve_drive_node(path=parent_path)
        parent.mkdir(name)

    def upload_file(self, *, parent_path: str, filename: str, content: bytes) -> None:
        parent = self._resolve_drive_node(path=parent_path)
        fileobj = NamedBytesIO(content, name=filename)
        parent.upload(fileobj)

    def rename_node(self, *, path: str, new_name: str) -> None:
        self._resolve_drive_node(path=path).rename(new_name)

    def delete_node(self, *, path: str) -> None:
        self._resolve_drive_node(path=path).delete()
