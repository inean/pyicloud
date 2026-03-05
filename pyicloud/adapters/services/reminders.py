"""Legacy-backed adapter for reminders domain operations."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any

from pyicloud.ports import RemindersServicePort

from .clients.reminders import LegacyRemindersClient, RemindersClient
from .mappers.reminders import map_reminder_collections
from .runtime import LegacyServicesAdapterBase


class RemindersServiceAdapter(LegacyServicesAdapterBase, RemindersServicePort):
    """Map reminders operations to the reminders service port contract."""

    def _reminders_client(self, *, username: str) -> RemindersClient:
        return LegacyRemindersClient(runtime=self._runtime, username=username)

    def reminder_lists(self, *, username: str) -> Mapping[str, Sequence[Mapping[str, Any]]]:
        return map_reminder_collections(self._reminders_client(username=username).collections())

    def create_reminder(
        self,
        *,
        username: str,
        title: str,
        description: str = "",
        collection: str | None = None,
        due_date: datetime | None = None,
    ) -> bool:
        return self._reminders_client(username=username).create_reminder(
            title=title,
            description=description,
            collection=collection,
            due_date=due_date,
        )
