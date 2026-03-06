"""Legacy-backed adapter for reminders domain operations."""

from __future__ import annotations

from datetime import datetime

from pyicloud.adapters.services.clients.reminders import LegacyRemindersClient, RemindersClient
from pyicloud.adapters.services.mappers.reminders import map_reminder_collections
from pyicloud.adapters.services.runtime import ServicesAdapterBase
from pyicloud.contexts.services.contracts.services import RemindersServicePort
from pyicloud.domain import ReminderListsDTO


class RemindersServiceAdapter(ServicesAdapterBase, RemindersServicePort):
    """Map reminders operations to the reminders service port contract."""

    def _reminders_client(self, *, username: str) -> RemindersClient:
        return LegacyRemindersClient(runtime=self._runtime, username=username)

    async def reminder_lists(self, *, username: str) -> ReminderListsDTO:
        collections = await self._run_blocking(lambda: self._reminders_client(username=username).collections())
        return map_reminder_collections(collections)

    async def create_reminder(
        self,
        *,
        username: str,
        title: str,
        description: str = "",
        collection: str | None = None,
        due_date: datetime | None = None,
    ) -> bool:
        return await self._run_blocking(
            lambda: self._reminders_client(username=username).create_reminder(
                title=title,
                description=description,
                collection=collection,
                due_date=due_date,
            )
        )
