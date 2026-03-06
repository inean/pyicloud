"""Domain mappers for typed drive client views."""

from __future__ import annotations

from pyicloud.adapters.services.clients.drive import DriveNodeView
from pyicloud.domain import DriveNodeDTO


def map_drive_node(view: DriveNodeView) -> DriveNodeDTO:
    payload: DriveNodeDTO = {
        "path": view.path,
        "name": view.name,
        "type": view.node_type,
        "size": view.size,
        "date_changed": view.date_changed,
        "date_modified": view.date_modified,
        "date_last_open": view.date_last_open,
    }
    if view.children is not None:
        payload["children"] = [dict(child) for child in view.children]
    return payload
