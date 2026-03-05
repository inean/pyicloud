"""Legacy-backed adapter for calendar domain operations."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any

from pyicloud.ports import CalendarServicePort

from .runtime import LegacyServicesAdapterBase


class CalendarServiceAdapter(LegacyServicesAdapterBase, CalendarServicePort):
    """Map calendar operations to the calendar service port contract."""

    def calendars(self, *, username: str) -> Sequence[Mapping[str, Any]]:
        calendars = self._services(username=username).calendar.calendars()
        return [dict(item) for item in calendars]

    def events(
        self,
        *,
        username: str,
        from_dt: datetime | None = None,
        to_dt: datetime | None = None,
    ) -> Sequence[Mapping[str, Any]]:
        events = self._services(username=username).calendar.events(from_dt=from_dt, to_dt=to_dt) or []
        return [dict(item) for item in events]

    def event_detail(self, *, username: str, calendar_guid: str, event_guid: str) -> Mapping[str, Any]:
        event = self._services(username=username).calendar.get_event_detail(pguid=calendar_guid, guid=event_guid)
        return dict(event)
