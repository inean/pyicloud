"""Legacy-backed adapter for photos domain operations."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from itertools import islice
from typing import Any

from pyicloud.ports import PhotosServicePort

from .runtime import LegacyServicesAdapterBase, LegacyServicesRuntime


class PhotosServiceAdapter(LegacyServicesAdapterBase, PhotosServicePort):
    """Map photo library operations to the photos service port contract."""

    @staticmethod
    def _photo_asset_metadata(*, album: str, asset: Any) -> dict[str, Any]:
        created = getattr(asset, "created", None)
        if isinstance(created, datetime):
            created_value: str | None = created.isoformat()
        elif created is None:
            created_value = None
        else:
            created_value = str(created)
        width, height = asset.dimensions
        versions = {
            name: {
                "filename": value.get("filename"),
                "width": value.get("width"),
                "height": value.get("height"),
                "size": value.get("size"),
                "type": value.get("type"),
            }
            for name, value in asset.versions.items()
        }
        return {
            "id": str(asset.id),
            "album": album,
            "filename": str(asset.filename),
            "size": int(asset.size),
            "created": created_value,
            "width": int(width),
            "height": int(height),
            "versions": versions,
        }

    def _photo_album(self, *, username: str, album: str):
        photos = self._services(username=username).photos
        albums = photos.albums
        if album not in albums:
            raise KeyError(f"Photo album not found: {album}")
        return albums[album]

    def _photo_asset(self, *, username: str, asset_id: str, album: str):
        for asset in self._photo_album(username=username, album=album).photos:
            if str(asset.id) == asset_id:
                return asset
        raise KeyError(f"Photo asset not found: {asset_id}")

    def list_albums(self, *, username: str) -> Sequence[Mapping[str, Any]]:
        albums = self._services(username=username).photos.albums
        return [{"name": str(name), "count": len(album)} for name, album in albums.items()]

    def list_assets(
        self,
        *,
        username: str,
        album: str = "All Photos",
        limit: int = 100,
        offset: int = 0,
    ) -> Sequence[Mapping[str, Any]]:
        album_obj = self._photo_album(username=username, album=album)
        assets = islice(album_obj.photos, offset, offset + limit)
        return [self._photo_asset_metadata(album=album, asset=asset) for asset in assets]

    def asset_metadata(self, *, username: str, asset_id: str, album: str = "All Photos") -> Mapping[str, Any]:
        asset = self._photo_asset(username=username, asset_id=asset_id, album=album)
        return self._photo_asset_metadata(album=album, asset=asset)

    def asset_content(
        self,
        *,
        username: str,
        asset_id: str,
        album: str = "All Photos",
        version: str = "original",
    ) -> bytes:
        asset = self._photo_asset(username=username, asset_id=asset_id, album=album)
        response = asset.download(version=version, stream=True)
        if response is None:
            raise KeyError(f"Photo version not found: {version}")
        return LegacyServicesRuntime.stream_bytes(response)
