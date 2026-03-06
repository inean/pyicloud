"""Domain mappers for typed calendar client views."""

from __future__ import annotations

from pyicloud.adapters.services.clients.calendar import CalendarEventDetailView, CalendarEventView, CalendarView
from pyicloud.domain import CalendarDTO, CalendarEventDetailDTO, CalendarEventDTO


def map_calendar(view: CalendarView) -> CalendarDTO:
    return dict(view.payload)


def map_calendar_event(view: CalendarEventView) -> CalendarEventDTO:
    return dict(view.payload)


def map_calendar_event_detail(view: CalendarEventDetailView) -> CalendarEventDetailDTO:
    return dict(view.payload)
