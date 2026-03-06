"""Calendar API routes."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from pyicloud.application.core_services import CoreServicesApi

from ..dependencies import get_core_services, get_username
from ..responses import ok

router = APIRouter()


@router.get("/v1/calendar/calendars")
async def calendar_calendars(
    username: str = Depends(get_username),
    service: CoreServicesApi = Depends(get_core_services),
) -> Any:
    return ok(await service.calendar_calendars(username=username))


@router.get("/v1/calendar/events")
async def calendar_events(
    from_dt: datetime | None = Query(default=None),
    to_dt: datetime | None = Query(default=None),
    username: str = Depends(get_username),
    service: CoreServicesApi = Depends(get_core_services),
) -> Any:
    return ok(await service.calendar_events(username=username, from_dt=from_dt, to_dt=to_dt))


@router.get("/v1/calendar/event-detail")
async def calendar_event_detail(
    calendar_guid: str = Query(..., min_length=1),
    event_guid: str = Query(..., min_length=1),
    username: str = Depends(get_username),
    service: CoreServicesApi = Depends(get_core_services),
) -> Any:
    try:
        return ok(
            await service.calendar_event_detail(
                username=username,
                calendar_guid=calendar_guid,
                event_guid=event_guid,
            )
        )
    except KeyError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
