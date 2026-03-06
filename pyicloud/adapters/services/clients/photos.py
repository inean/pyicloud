"""Typed client for legacy photos library operations."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from itertools import islice
from typing import Any, Protocol

from pyicloud.adapters.services.clients.common import Pagination
from pyicloud.adapters.services.content import PhotoBinaryContentAdapter
from pyicloud.platform.provider.runtime import ServiceRuntime


@dataclass(frozen=True)
class PhotoAlbumView:
    name: str
    count: int


@dataclass(frozen=True)
class PhotoVersionView:
    filename: str | None
    width: int | None
    height: int | None
    size: int | None
    content_type: str | None


@dataclass(frozen=True)
class PhotoAssetView:
    asset_id: str
    album: str
    filename: str
    size: int
    created: str | None
    width: int
    height: int
    versions: Mapping[str, PhotoVersionView]


class PhotosClient(Protocol):
    def albums(self) -> Sequence[PhotoAlbumView]: ...
    def assets(self, *, album: str, pagination: Pagination | None = None) -> Sequence[PhotoAssetView]: ...
    def asset_metadata(self, *, asset_id: str, album: str) -> PhotoAssetView: ...
    def asset_content(self, *, asset_id: str, album: str, version: str = "original") -> bytes: ...


class LegacyPhotosClient:
    """Query photos library data from legacy services with typed views."""

    def __init__(
        self,
        *,
        runtime: ServiceRuntime,
        username: str,
        binary_content: PhotoBinaryContentAdapter | None = None,
    ):
        self._runtime = runtime
        self._username = username
        self._binary_content = binary_content or PhotoBinaryContentAdapter()

    def _photo_album(self, *, album: str):
        photos = self._runtime.services(username=self._username).photos
        albums = photos.albums
        if album not in albums:
            raise KeyError(f"Photo album not found: {album}")
        return albums[album]

    def _photo_asset(self, *, asset_id: str, album: str):
        for asset in self._photo_album(album=album).photos:
            if str(asset.id) == asset_id:
                return asset
        raise KeyError(f"Photo asset not found: {asset_id}")

    @staticmethod
    def _slice(items: Sequence[Any], *, pagination: Pagination | None) -> Sequence[Any]:
        if pagination is None:
            return list(items)
        start = max(0, pagination.offset)
        end = start + max(0, pagination.limit)
        return list(items[start:end])

    @staticmethod
    def _asset_view(*, album: str, asset: Any) -> PhotoAssetView:
        created = getattr(asset, "created", None)
        if isinstance(created, datetime):
            created_value: str | None = created.isoformat()
        elif created is None:
            created_value = None
        else:
            created_value = str(created)
        width, height = asset.dimensions
        versions: dict[str, PhotoVersionView] = {}
        for name, value in asset.versions.items():
            payload = value if isinstance(value, Mapping) else {}
            versions[str(name)] = PhotoVersionView(
                filename=str(payload.get("filename")) if payload.get("filename") is not None else None,
                width=int(payload["width"]) if payload.get("width") is not None else None,
                height=int(payload["height"]) if payload.get("height") is not None else None,
                size=int(payload["size"]) if payload.get("size") is not None else None,
                content_type=str(payload.get("type")) if payload.get("type") is not None else None,
            )

        return PhotoAssetView(
            asset_id=str(asset.id),
            album=album,
            filename=str(asset.filename),
            size=int(asset.size),
            created=created_value,
            width=int(width),
            height=int(height),
            versions=versions,
        )

    def albums(self) -> Sequence[PhotoAlbumView]:
        albums = self._runtime.services(username=self._username).photos.albums
        return [PhotoAlbumView(name=str(name), count=len(album)) for name, album in albums.items()]

    def assets(self, *, album: str, pagination: Pagination | None = None) -> Sequence[PhotoAssetView]:
        album_obj = self._photo_album(album=album)
        assets = list(islice(album_obj.photos, 0, None))
        selected_assets = self._slice(assets, pagination=pagination)
        return [self._asset_view(album=album, asset=asset) for asset in selected_assets]

    def asset_metadata(self, *, asset_id: str, album: str) -> PhotoAssetView:
        return self._asset_view(album=album, asset=self._photo_asset(asset_id=asset_id, album=album))

    def asset_content(self, *, asset_id: str, album: str, version: str = "original") -> bytes:
        asset = self._photo_asset(asset_id=asset_id, album=album)
        return self._binary_content.download(asset=asset, version=version)
