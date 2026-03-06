"""Typed client for legacy calendar operations."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from pyicloud.adapters.services.clients.common import Pagination, TimeRangeFilter
from pyicloud.adapters.services.runtime import ServiceRuntime


@dataclass(frozen=True)
class CalendarView:
    payload: Mapping[str, Any]


@dataclass(frozen=True)
class CalendarEventView:
    payload: Mapping[str, Any]


@dataclass(frozen=True)
class CalendarEventDetailView:
    payload: Mapping[str, Any]


class CalendarClient(Protocol):
    def calendars(self, *, pagination: Pagination | None = None) -> Sequence[CalendarView]: ...
    def events(
        self,
        *,
        time_range: TimeRangeFilter | None = None,
        pagination: Pagination | None = None,
    ) -> Sequence[CalendarEventView]: ...
    def event_detail(self, *, calendar_guid: str, event_guid: str) -> CalendarEventDetailView: ...


class LegacyCalendarClient:
    """Query calendar data from legacy service objects with typed views."""

    def __init__(self, *, runtime: ServiceRuntime, username: str):
        self._runtime = runtime
        self._username = username

    @staticmethod
    def _slice(items: Sequence[Mapping[str, Any]], *, pagination: Pagination | None) -> Sequence[Mapping[str, Any]]:
        if pagination is None:
            return list(items)
        start = max(0, pagination.offset)
        end = start + max(0, pagination.limit)
        return list(items[start:end])

    def calendars(self, *, pagination: Pagination | None = None) -> Sequence[CalendarView]:
        calendars = self._runtime.services(username=self._username).calendar.calendars()
        payloads = [dict(item) for item in calendars]
        return [CalendarView(payload=item) for item in self._slice(payloads, pagination=pagination)]

    def events(
        self,
        *,
        time_range: TimeRangeFilter | None = None,
        pagination: Pagination | None = None,
    ) -> Sequence[CalendarEventView]:
        query = time_range or TimeRangeFilter()
        events = (
            self._runtime.services(username=self._username).calendar.events(
                from_dt=query.from_dt,
                to_dt=query.to_dt,
            )
            or []
        )
        payloads = [dict(item) for item in events]
        return [CalendarEventView(payload=item) for item in self._slice(payloads, pagination=pagination)]

    def event_detail(self, *, calendar_guid: str, event_guid: str) -> CalendarEventDetailView:
        event = self._runtime.services(username=self._username).calendar.get_event_detail(
            pguid=calendar_guid,
            guid=event_guid,
        )
        return CalendarEventDetailView(payload=dict(event))
