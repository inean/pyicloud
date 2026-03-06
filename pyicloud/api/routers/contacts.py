"""Contacts API routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from pyicloud.application.core_services import CoreServicesApi

from ..dependencies import get_core_services, get_username
from ..responses import ok

router = APIRouter()


@router.get("/v1/contacts")
async def contacts_list(
    username: str = Depends(get_username),
    service: CoreServicesApi = Depends(get_core_services),
) -> Any:
    return ok(await service.contacts_all(username=username))
