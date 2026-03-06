"""Ubiquity API routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import ValidationError

from pyicloud.application.core_services import CoreServicesApi

from ..dependencies import get_core_services, get_username
from ..responses import ok
from ..schemas import UbiquityFileMetadataResponse

router = APIRouter()


@router.get("/v1/ubiquity/tree")
async def ubiquity_tree(
    path: str = Query(default="/"),
    username: str = Depends(get_username),
    service: CoreServicesApi = Depends(get_core_services),
) -> Any:
    try:
        return ok(await service.ubiquity_tree(username=username, path=path))
    except KeyError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err


@router.get("/v1/ubiquity/file")
async def ubiquity_file(
    path: str = Query(...),
    download: bool = Query(default=False),
    username: str = Depends(get_username),
    service: CoreServicesApi = Depends(get_core_services),
) -> Any:
    try:
        if not download:
            metadata = await service.ubiquity_file_metadata(username=username, path=path)
            return ok(UbiquityFileMetadataResponse.model_validate(metadata))
        metadata = UbiquityFileMetadataResponse.model_validate(
            await service.ubiquity_file_metadata(username=username, path=path)
        )
        content = await service.ubiquity_file_content(username=username, path=path)
    except ValidationError as err:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Invalid ubiquity metadata: {err}",
        ) from err
    except KeyError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err

    filename = metadata.name.strip() or "file.bin"
    return StreamingResponse(
        iter([content]),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
