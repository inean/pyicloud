"""Photos API routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import ValidationError

from pyicloud.application.core_services import CoreServicesApi

from ..dependencies import get_core_services, get_username
from ..responses import ok
from ..schemas import DataEnvelope, PhotoAssetMetadataResponse

router = APIRouter()


@router.get("/v1/photos/albums")
async def photos_albums(
    username: str = Depends(get_username),
    service: CoreServicesApi = Depends(get_core_services),
) -> Any:
    return ok(await service.photos_albums(username=username))


@router.get("/v1/photos/assets")
async def photos_assets(
    album: str = Query(default="All Photos"),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    username: str = Depends(get_username),
    service: CoreServicesApi = Depends(get_core_services),
) -> Any:
    try:
        return ok(await service.photos_assets(username=username, album=album, limit=limit, offset=offset))
    except KeyError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err


@router.get("/v1/photos/asset", response_model=DataEnvelope)
async def photos_asset(
    asset_id: str = Query(..., min_length=1),
    album: str = Query(default="All Photos"),
    username: str = Depends(get_username),
    service: CoreServicesApi = Depends(get_core_services),
) -> DataEnvelope:
    try:
        metadata = await service.photo_asset_metadata(username=username, asset_id=asset_id, album=album)
        return ok(PhotoAssetMetadataResponse.model_validate(metadata))
    except KeyError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err


@router.get("/v1/photos/download")
async def photos_download(
    asset_id: str = Query(..., min_length=1),
    album: str = Query(default="All Photos"),
    version: str = Query(default="original", min_length=1),
    username: str = Depends(get_username),
    service: CoreServicesApi = Depends(get_core_services),
) -> StreamingResponse:
    try:
        metadata = PhotoAssetMetadataResponse.model_validate(
            await service.photo_asset_metadata(username=username, asset_id=asset_id, album=album)
        )
        content = await service.photo_asset_content(
            username=username,
            asset_id=asset_id,
            album=album,
            version=version,
        )
    except ValidationError as err:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Invalid photo metadata: {err}",
        ) from err
    except KeyError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
    filename = metadata.filename.strip() or f"{asset_id}.bin"
    return StreamingResponse(
        iter([content]),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
