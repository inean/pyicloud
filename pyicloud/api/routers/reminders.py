"""Reminders API routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status

from pyicloud.application.core_services import CoreServicesApi

from ..dependencies import get_core_services, get_username
from ..responses import ok
from ..schemas import DataEnvelope, ReminderCreateRequest, SimpleOkResponse

router = APIRouter()


@router.get("/v1/reminders")
async def reminders_list(
    username: str = Depends(get_username),
    service: CoreServicesApi = Depends(get_core_services),
) -> Any:
    return ok(await service.reminders_lists(username=username))


@router.post("/v1/reminders", response_model=DataEnvelope)
async def reminders_create(
    payload: ReminderCreateRequest,
    username: str = Depends(get_username),
    service: CoreServicesApi = Depends(get_core_services),
) -> DataEnvelope:
    created = await service.reminders_create(
        username=username,
        title=payload.title,
        description=payload.description,
        collection=payload.collection,
        due_date=payload.due_date,
    )
    if not created:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Reminder creation failed")
    return ok(SimpleOkResponse(detail="Reminder created"))
