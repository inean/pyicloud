"""Legacy-backed adapter for calendar domain operations."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any

from pyicloud.ports import CalendarServicePort

from .clients.calendar import CalendarClient, LegacyCalendarClient
from .clients.common import TimeRangeFilter
from .mappers.calendar import map_calendar, map_calendar_event, map_calendar_event_detail
from .runtime import LegacyServicesAdapterBase


class CalendarServiceAdapter(LegacyServicesAdapterBase, CalendarServicePort):
    """Map calendar operations to the calendar service port contract."""

    def _calendar_client(self, *, username: str) -> CalendarClient:
        return LegacyCalendarClient(runtime=self._runtime, username=username)

    async def calendars(self, *, username: str) -> Sequence[Mapping[str, Any]]:
        views = await self._run_blocking(lambda: self._calendar_client(username=username).calendars())
        return [map_calendar(view) for view in views]

    async def events(
        self,
        *,
        username: str,
        from_dt: datetime | None = None,
        to_dt: datetime | None = None,
    ) -> Sequence[Mapping[str, Any]]:
        views = await self._run_blocking(
            lambda: self._calendar_client(username=username).events(
                time_range=TimeRangeFilter(from_dt=from_dt, to_dt=to_dt),
            )
        )
        return [map_calendar_event(view) for view in views]

    async def event_detail(self, *, username: str, calendar_guid: str, event_guid: str) -> Mapping[str, Any]:
        view = await self._run_blocking(
            lambda: self._calendar_client(username=username).event_detail(
                calendar_guid=calendar_guid,
                event_guid=event_guid,
            )
        )
        return map_calendar_event_detail(view)
