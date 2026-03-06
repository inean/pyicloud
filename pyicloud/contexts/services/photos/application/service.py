"""Photos application service."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence

from pyicloud.contexts.services.contracts.services import PhotosServicePort
from pyicloud.domain import PhotoAlbumDTO, PhotoAssetDTO
from pyicloud.upstream import bind_upstream_context


class PhotosApplicationService:
    """Orchestrate photos operations over the photos outbound port."""

    def __init__(self, *, port: PhotosServicePort):
        self._port = port

    @staticmethod
    async def _run_with_operation[T](
        *,
        username: str,
        operation: str,
        call: Callable[[], Awaitable[T]],
    ) -> T:
        with bind_upstream_context(username=username, operation=operation, step=operation.split(".")[-1]):
            return await call()

    async def list_albums(self, *, username: str) -> Sequence[PhotoAlbumDTO]:
        return await self._run_with_operation(
            username=username,
            operation="photos.albums",
            call=lambda: self._port.list_albums(username=username),
        )

    async def list_assets(
        self,
        *,
        username: str,
        album: str = "All Photos",
        limit: int = 100,
        offset: int = 0,
    ) -> Sequence[PhotoAssetDTO]:
        return await self._run_with_operation(
            username=username,
            operation="photos.assets",
            call=lambda: self._port.list_assets(username=username, album=album, limit=limit, offset=offset),
        )

    async def asset_metadata(self, *, username: str, asset_id: str, album: str = "All Photos") -> PhotoAssetDTO:
        return await self._run_with_operation(
            username=username,
            operation="photos.asset_metadata",
            call=lambda: self._port.asset_metadata(username=username, asset_id=asset_id, album=album),
        )

    async def asset_content(
        self,
        *,
        username: str,
        asset_id: str,
        album: str = "All Photos",
        version: str = "original",
    ) -> bytes:
        return await self._run_with_operation(
            username=username,
            operation="photos.asset_content",
            call=lambda: self._port.asset_content(
                username=username,
                asset_id=asset_id,
                album=album,
                version=version,
            ),
        )
