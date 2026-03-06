"""Typed client for legacy reminders operations."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from pyicloud.adapters.services.clients.common import Pagination
from pyicloud.adapters.services.runtime import ServiceRuntime


@dataclass(frozen=True)
class ReminderView:
    payload: Mapping[str, Any]


@dataclass(frozen=True)
class ReminderCollectionView:
    title: str
    reminders: Sequence[ReminderView]


class RemindersClient(Protocol):
    def collections(self, *, pagination: Pagination | None = None) -> Sequence[ReminderCollectionView]: ...
    def create_reminder(
        self,
        *,
        title: str,
        description: str = "",
        collection: str | None = None,
        due_date: datetime | None = None,
    ) -> bool: ...


class LegacyRemindersClient:
    """Query/mutate reminder data from legacy service objects with typed views."""

    def __init__(self, *, runtime: ServiceRuntime, username: str):
        self._runtime = runtime
        self._username = username

    def collections(self, *, pagination: Pagination | None = None) -> Sequence[ReminderCollectionView]:
        lists = self._runtime.services(username=self._username).reminders.lists
        titles = list(lists.keys())
        if pagination is not None:
            start = max(0, pagination.offset)
            end = start + max(0, pagination.limit)
            titles = titles[start:end]
        collections: list[ReminderCollectionView] = []
        for title in titles:
            reminders = [ReminderView(payload=dict(item)) for item in lists[title]]
            collections.append(ReminderCollectionView(title=str(title), reminders=reminders))
        return collections

    def create_reminder(
        self,
        *,
        title: str,
        description: str = "",
        collection: str | None = None,
        due_date: datetime | None = None,
    ) -> bool:
        return bool(
            self._runtime.services(username=self._username).reminders.post(
                title=title,
                description=description,
                collection=collection,
                due_date=due_date,
            )
        )
