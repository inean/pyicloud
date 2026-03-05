"""Domain mappers for typed photos client views."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pyicloud.adapters.services.clients.photos import PhotoAlbumView, PhotoAssetView, PhotoVersionView


def map_photo_album(view: PhotoAlbumView) -> Mapping[str, Any]:
    return {"name": view.name, "count": view.count}


def map_photo_version(view: PhotoVersionView) -> Mapping[str, Any]:
    return {
        "filename": view.filename,
        "width": view.width,
        "height": view.height,
        "size": view.size,
        "type": view.content_type,
    }


def map_photo_asset(view: PhotoAssetView) -> Mapping[str, Any]:
    return {
        "id": view.asset_id,
        "album": view.album,
        "filename": view.filename,
        "size": view.size,
        "created": view.created,
        "width": view.width,
        "height": view.height,
        "versions": {name: map_photo_version(version) for name, version in view.versions.items()},
    }
