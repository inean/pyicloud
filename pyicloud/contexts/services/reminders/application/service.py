"""Reminders application service."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import datetime

from pyicloud.contexts.services.contracts.services import RemindersServicePort
from pyicloud.domain import ReminderListsDTO
from pyicloud.upstream import bind_upstream_context


class RemindersApplicationService:
    """Orchestrate reminders operations over the reminders outbound port."""

    def __init__(self, *, port: RemindersServicePort):
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

    async def reminder_lists(self, *, username: str) -> ReminderListsDTO:
        return await self._run_with_operation(
            username=username,
            operation="reminders.lists",
            call=lambda: self._port.reminder_lists(username=username),
        )

    async def create_reminder(
        self,
        *,
        username: str,
        title: str,
        description: str = "",
        collection: str | None = None,
        due_date: datetime | None = None,
    ) -> bool:
        return await self._run_with_operation(
            username=username,
            operation="reminders.create",
            call=lambda: self._port.create_reminder(
                username=username,
                title=title,
                description=description,
                collection=collection,
                due_date=due_date,
            ),
        )
