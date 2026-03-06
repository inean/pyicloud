"""Typed client for legacy ubiquity file library operations."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from pyicloud.adapters.services.clients.common import Pagination
from pyicloud.adapters.services.content import UbiquityBinaryContentAdapter
from pyicloud.adapters.services.runtime import ServiceRuntime


@dataclass(frozen=True)
class UbiquityNodeView:
    path: str
    item_id: int | str
    name: str
    node_type: str
    size: int | None
    modified: str | None
    children: Sequence[UbiquityNodeView] | None = None


class UbiquityClient(Protocol):
    def tree(self, *, path: str, pagination: Pagination | None = None) -> UbiquityNodeView: ...
    def metadata(self, *, path: str) -> UbiquityNodeView: ...
    def content(self, *, path: str) -> bytes: ...


class LegacyUbiquityClient:
    """Query ubiquity tree/file data from legacy services with typed views."""

    def __init__(
        self,
        *,
        runtime: ServiceRuntime,
        username: str,
        binary_content: UbiquityBinaryContentAdapter | None = None,
    ):
        self._runtime = runtime
        self._username = username
        self._binary_content = binary_content or UbiquityBinaryContentAdapter()

    def _resolve_ubiquity_node(self, *, path: str):
        files_root = self._runtime.services(username=self._username).files
        return ServiceRuntime.resolve_path(root=files_root, path=path)

    @staticmethod
    def _child_path(parent_path: str, name: str) -> str:
        parent = parent_path or "/"
        if parent == "/":
            return f"/{name}"
        return f"{parent.rstrip('/')}/{name}"

    @staticmethod
    def _slice(items: Sequence[Any], *, pagination: Pagination | None) -> Sequence[Any]:
        if pagination is None:
            return list(items)
        start = max(0, pagination.offset)
        end = start + max(0, pagination.limit)
        return list(items[start:end])

    @staticmethod
    def _node_view(
        *,
        path: str,
        node: Any,
        children: Sequence[UbiquityNodeView] | None = None,
    ) -> UbiquityNodeView:
        modified = getattr(node, "modified", None)
        if isinstance(modified, datetime):
            modified_value: str | None = modified.isoformat()
        elif modified is None:
            modified_value = None
        else:
            modified_value = str(modified)
        return UbiquityNodeView(
            path=path or "/",
            item_id=node.item_id,
            name=node.name,
            node_type=node.type,
            size=int(node.size) if node.size is not None else None,
            modified=modified_value,
            children=children,
        )

    def tree(self, *, path: str, pagination: Pagination | None = None) -> UbiquityNodeView:
        resolved_path = path or "/"
        node = self._resolve_ubiquity_node(path=resolved_path)
        child_views: list[UbiquityNodeView] = []
        try:
            children = list(node.get_children())
        except Exception:  # noqa: BLE001
            children = []
        for child in self._slice(children, pagination=pagination):
            child_views.append(
                self._node_view(
                    path=self._child_path(resolved_path, str(child.name)),
                    node=child,
                )
            )
        return self._node_view(path=resolved_path, node=node, children=child_views)

    def metadata(self, *, path: str) -> UbiquityNodeView:
        return self._node_view(path=path, node=self._resolve_ubiquity_node(path=path))

    def content(self, *, path: str) -> bytes:
        node = self._resolve_ubiquity_node(path=path)
        return self._binary_content.read_file(node=node)
