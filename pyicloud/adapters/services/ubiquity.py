"""Legacy-backed adapter for ubiquity file library operations."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from pyicloud.ports import UbiquityServicePort

from .runtime import LegacyServicesAdapterBase, LegacyServicesRuntime


class UbiquityServiceAdapter(LegacyServicesAdapterBase, UbiquityServicePort):
    """Map ubiquity operations to the ubiquity service port contract."""

    def _resolve_ubiquity_node(self, *, username: str, path: str):
        files_root = self._services(username=username).files
        return LegacyServicesRuntime.resolve_path(root=files_root, path=path)

    @staticmethod
    def _ubiquity_node_metadata(path: str, node: Any) -> dict[str, Any]:
        modified = getattr(node, "modified", None)
        if isinstance(modified, datetime):
            modified_value: str | None = modified.isoformat()
        elif modified is None:
            modified_value = None
        else:
            modified_value = str(modified)
        return {
            "path": path or "/",
            "item_id": node.item_id,
            "name": node.name,
            "type": node.type,
            "size": node.size,
            "modified": modified_value,
        }

    @staticmethod
    def _child_path(parent_path: str, name: str) -> str:
        parent = parent_path or "/"
        if parent == "/":
            return f"/{name}"
        return f"{parent.rstrip('/')}/{name}"

    def ubiquity_tree(self, *, username: str, path: str) -> Mapping[str, Any]:
        resolved_path = path or "/"
        node = self._resolve_ubiquity_node(username=username, path=resolved_path)
        data = self._ubiquity_node_metadata(path=resolved_path, node=node)
        children: list[Mapping[str, Any]] = []
        try:
            for child in node.get_children():
                children.append(
                    self._ubiquity_node_metadata(
                        path=self._child_path(resolved_path, str(child.name)),
                        node=child,
                    )
                )
        except Exception:  # noqa: BLE001
            children = []
        data["children"] = children
        return data

    def ubiquity_file_metadata(self, *, username: str, path: str) -> Mapping[str, Any]:
        return self._ubiquity_node_metadata(path=path, node=self._resolve_ubiquity_node(username=username, path=path))

    def ubiquity_file_content(self, *, username: str, path: str) -> bytes:
        node = self._resolve_ubiquity_node(username=username, path=path)
        if str(node.type) != "file":
            raise KeyError("Ubiquity path is not a file")
        with node.open(stream=True) as response:
            return LegacyServicesRuntime.stream_bytes(response)
