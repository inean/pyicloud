"""Legacy-backed adapter for photos domain operations."""

from __future__ import annotations

from collections.abc import Sequence

from pyicloud.adapters.services.clients.common import Pagination
from pyicloud.adapters.services.clients.photos import LegacyPhotosClient, PhotosClient
from pyicloud.adapters.services.mappers.photos import map_photo_album, map_photo_asset
from pyicloud.contexts.services.contracts.services import PhotosServicePort
from pyicloud.domain import PhotoAlbumDTO, PhotoAssetDTO
from pyicloud.platform.provider.runtime import ServicesAdapterBase


class PhotosServiceAdapter(ServicesAdapterBase, PhotosServicePort):
    """Map photo library operations to the photos service port contract."""

    def _photos_client(self, *, username: str) -> PhotosClient:
        return LegacyPhotosClient(runtime=self._runtime, username=username)

    async def list_albums(self, *, username: str) -> Sequence[PhotoAlbumDTO]:
        views = await self._run_blocking(lambda: self._photos_client(username=username).albums())
        return [map_photo_album(view) for view in views]

    async def list_assets(
        self,
        *,
        username: str,
        album: str = "All Photos",
        limit: int = 100,
        offset: int = 0,
    ) -> Sequence[PhotoAssetDTO]:
        views = await self._run_blocking(
            lambda: self._photos_client(username=username).assets(
                album=album,
                pagination=Pagination(limit=limit, offset=offset),
            )
        )
        return [map_photo_asset(view) for view in views]

    async def asset_metadata(self, *, username: str, asset_id: str, album: str = "All Photos") -> PhotoAssetDTO:
        view = await self._run_blocking(
            lambda: self._photos_client(username=username).asset_metadata(asset_id=asset_id, album=album)
        )
        return map_photo_asset(view)

    async def asset_content(
        self,
        *,
        username: str,
        asset_id: str,
        album: str = "All Photos",
        version: str = "original",
    ) -> bytes:
        return await self._run_blocking(
            lambda: self._photos_client(username=username).asset_content(
                asset_id=asset_id,
                album=album,
                version=version,
            )
        )
