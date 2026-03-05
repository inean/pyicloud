"""Domain mappers for typed ubiquity client views."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pyicloud.adapters.services.clients.ubiquity import UbiquityNodeView


def map_ubiquity_node(view: UbiquityNodeView) -> Mapping[str, Any]:
    payload: dict[str, Any] = {
        "path": view.path,
        "item_id": view.item_id,
        "name": view.name,
        "type": view.node_type,
        "size": view.size,
        "modified": view.modified,
    }
    if view.children is not None:
        payload["children"] = [map_ubiquity_node(item) for item in view.children]
    return payload
