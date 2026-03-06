"""Drive API routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from fastapi.responses import StreamingResponse
from pydantic import ValidationError

from pyicloud.application.core_services import CoreServicesApi

from ..dependencies import get_core_services, get_username
from ..responses import ok
from ..schemas import (
    DataEnvelope,
    DriveCreateFolderRequest,
    DriveFileMetadataResponse,
    DriveRenameNodeRequest,
    SimpleOkResponse,
)

router = APIRouter()


@router.get("/v1/drive/tree")
async def drive_tree(
    path: str = Query(default="/"),
    username: str = Depends(get_username),
    service: CoreServicesApi = Depends(get_core_services),
) -> Any:
    return ok(await service.drive_tree(username=username, path=path))


@router.get("/v1/drive/file")
async def drive_file(
    path: str = Query(...),
    download: bool = Query(default=False),
    username: str = Depends(get_username),
    service: CoreServicesApi = Depends(get_core_services),
) -> Any:
    if not download:
        metadata = await service.drive_file_metadata(username=username, path=path)
        return ok(DriveFileMetadataResponse.model_validate(metadata))

    try:
        metadata = DriveFileMetadataResponse.model_validate(
            await service.drive_file_metadata(username=username, path=path)
        )
    except ValidationError as err:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"Invalid drive metadata: {err}") from err
    content = await service.drive_file_content(username=username, path=path)
    filename = metadata.name.strip() or "file.bin"
    return StreamingResponse(
        iter([content]),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/v1/drive/folders", response_model=DataEnvelope)
async def drive_folders(
    payload: DriveCreateFolderRequest,
    username: str = Depends(get_username),
    service: CoreServicesApi = Depends(get_core_services),
) -> DataEnvelope:
    await service.drive_create_folder(username=username, parent_path=payload.parent_path, name=payload.name)
    return ok(SimpleOkResponse(detail="Folder created"))


@router.post("/v1/drive/upload", response_model=DataEnvelope)
async def drive_upload(
    file: UploadFile = File(...),
    parent_path: str = Query(default="/"),
    username: str = Depends(get_username),
    service: CoreServicesApi = Depends(get_core_services),
) -> DataEnvelope:
    content = await file.read()
    await service.drive_upload_file(
        username=username,
        parent_path=parent_path,
        filename=file.filename or "upload.bin",
        content=content,
    )
    return ok(SimpleOkResponse(detail="File uploaded"))


@router.patch("/v1/drive/node", response_model=DataEnvelope)
async def drive_rename(
    payload: DriveRenameNodeRequest,
    username: str = Depends(get_username),
    service: CoreServicesApi = Depends(get_core_services),
) -> DataEnvelope:
    await service.drive_rename_node(username=username, path=payload.path, new_name=payload.new_name)
    return ok(SimpleOkResponse(detail="Node renamed"))


@router.delete("/v1/drive/node", response_model=DataEnvelope)
async def drive_delete(
    path: str = Query(...),
    username: str = Depends(get_username),
    service: CoreServicesApi = Depends(get_core_services),
) -> DataEnvelope:
    await service.drive_delete_node(username=username, path=path)
    return ok(SimpleOkResponse(detail="Node deleted"))
