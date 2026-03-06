"""Calendar application service."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from datetime import datetime

from pyicloud.contexts.services.contracts.services import CalendarServicePort
from pyicloud.domain import CalendarDTO, CalendarEventDetailDTO, CalendarEventDTO
from pyicloud.upstream import bind_upstream_context


class CalendarApplicationService:
    """Orchestrate calendar operations over the calendar outbound port."""

    def __init__(self, *, port: CalendarServicePort):
        self._port = port

    @staticmethod
    async def _run_with_operation[T](
        *,
        username: str,
        operation: str,
        call: Callable[[], Awaitable[T]],
    ) -> T:
        with bind_upstream_context(username=username, operation=operation, step=operation.split(".")[-1]):
            return await call()

    async def calendars(self, *, username: str) -> Sequence[CalendarDTO]:
        return await self._run_with_operation(
            username=username,
            operation="calendar.calendars",
            call=lambda: self._port.calendars(username=username),
        )

    async def events(
        self,
        *,
        username: str,
        from_dt: datetime | None = None,
        to_dt: datetime | None = None,
    ) -> Sequence[CalendarEventDTO]:
        return await self._run_with_operation(
            username=username,
            operation="calendar.events",
            call=lambda: self._port.events(username=username, from_dt=from_dt, to_dt=to_dt),
        )

    async def event_detail(self, *, username: str, calendar_guid: str, event_guid: str) -> CalendarEventDetailDTO:
        return await self._run_with_operation(
            username=username,
            operation="calendar.event_detail",
            call=lambda: self._port.event_detail(
                username=username,
                calendar_guid=calendar_guid,
                event_guid=event_guid,
            ),
        )
