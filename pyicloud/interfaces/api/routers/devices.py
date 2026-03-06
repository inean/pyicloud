"""Devices API routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Path, status

from pyicloud.application.core_services import CoreServicesApi

from ..dependencies import get_core_services, get_username
from ..responses import ok
from ..schemas import (
    DataEnvelope,
    DeviceLostModeRequest,
    DeviceMessageRequest,
    DevicePlaySoundRequest,
    SimpleOkResponse,
)

router = APIRouter()


@router.get("/v1/devices")
async def devices_list(
    username: str = Depends(get_username),
    service: CoreServicesApi = Depends(get_core_services),
) -> Any:
    return ok(await service.list_devices(username=username))


@router.get("/v1/devices/{device_id}/location")
async def devices_location(
    device_id: str = Path(...),
    username: str = Depends(get_username),
    service: CoreServicesApi = Depends(get_core_services),
) -> Any:
    try:
        return ok(await service.device_location(username=username, device_id=device_id))
    except KeyError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err


@router.get("/v1/devices/{device_id}/status")
async def devices_status(
    device_id: str = Path(...),
    username: str = Depends(get_username),
    service: CoreServicesApi = Depends(get_core_services),
) -> Any:
    try:
        return ok(await service.device_status(username=username, device_id=device_id))
    except KeyError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err


@router.post("/v1/devices/{device_id}/actions/play-sound", response_model=DataEnvelope)
async def devices_play_sound(
    payload: DevicePlaySoundRequest,
    device_id: str = Path(...),
    username: str = Depends(get_username),
    service: CoreServicesApi = Depends(get_core_services),
) -> DataEnvelope:
    try:
        await service.device_play_sound(username=username, device_id=device_id, subject=payload.subject)
    except KeyError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
    return ok(SimpleOkResponse(detail="Sound command sent"))


@router.post("/v1/devices/{device_id}/actions/message", response_model=DataEnvelope)
async def devices_message(
    payload: DeviceMessageRequest,
    device_id: str = Path(...),
    username: str = Depends(get_username),
    service: CoreServicesApi = Depends(get_core_services),
) -> DataEnvelope:
    try:
        await service.device_message(
            username=username,
            device_id=device_id,
            subject=payload.subject,
            message=payload.message,
            sounds=payload.sounds,
        )
    except KeyError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
    return ok(SimpleOkResponse(detail="Message command sent"))


@router.post("/v1/devices/{device_id}/actions/lost-mode", response_model=DataEnvelope)
async def devices_lost_mode(
    payload: DeviceLostModeRequest,
    device_id: str = Path(...),
    username: str = Depends(get_username),
    service: CoreServicesApi = Depends(get_core_services),
) -> DataEnvelope:
    try:
        await service.device_lost_mode(
            username=username,
            device_id=device_id,
            number=payload.number,
            text=payload.text,
            newpasscode=payload.newpasscode,
        )
    except KeyError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
    return ok(SimpleOkResponse(detail="Lost mode command sent"))
