"""Account API routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from pyicloud.application.core_services import CoreServicesApi

from ..dependencies import get_core_services, get_username
from ..responses import ok
from ..schemas import AccountStorageResponse, DataEnvelope

router = APIRouter()


@router.get("/v1/account/devices")
async def account_devices(
    username: str = Depends(get_username),
    service: CoreServicesApi = Depends(get_core_services),
) -> Any:
    return ok(await service.account_devices(username=username))


@router.get("/v1/account/family")
async def account_family(
    username: str = Depends(get_username),
    service: CoreServicesApi = Depends(get_core_services),
) -> Any:
    return ok(await service.account_family(username=username))


@router.get("/v1/account/storage", response_model=DataEnvelope)
async def account_storage(
    username: str = Depends(get_username),
    service: CoreServicesApi = Depends(get_core_services),
) -> DataEnvelope:
    return ok(AccountStorageResponse.model_validate(await service.account_storage(username=username)))
