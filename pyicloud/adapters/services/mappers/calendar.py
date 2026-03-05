"""Domain mappers for typed calendar client views."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pyicloud.adapters.services.clients.calendar import CalendarEventDetailView, CalendarEventView, CalendarView


def map_calendar(view: CalendarView) -> Mapping[str, Any]:
    return dict(view.payload)


def map_calendar_event(view: CalendarEventView) -> Mapping[str, Any]:
    return dict(view.payload)


def map_calendar_event_detail(view: CalendarEventDetailView) -> Mapping[str, Any]:
    return dict(view.payload)
