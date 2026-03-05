"""Legacy-backed adapter for reminders domain operations."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any

from pyicloud.ports import RemindersServicePort

from .runtime import LegacyServicesAdapterBase


class RemindersServiceAdapter(LegacyServicesAdapterBase, RemindersServicePort):
    """Map reminders operations to the reminders service port contract."""

    def reminder_lists(self, *, username: str) -> Mapping[str, Sequence[Mapping[str, Any]]]:
        lists = self._services(username=username).reminders.lists
        normalized: dict[str, list[Mapping[str, Any]]] = {}
        for title, reminders in lists.items():
            normalized[title] = [dict(item) for item in reminders]
        return normalized

    def create_reminder(
        self,
        *,
        username: str,
        title: str,
        description: str = "",
        collection: str | None = None,
        due_date: datetime | None = None,
    ) -> bool:
        return bool(
            self._services(username=username).reminders.post(
                title=title,
                description=description,
                collection=collection,
                due_date=due_date,
            )
        )
