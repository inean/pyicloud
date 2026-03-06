"""Domain mappers for typed reminders client views."""

from __future__ import annotations

from collections.abc import Sequence

from pyicloud.adapters.services.clients.reminders import ReminderCollectionView, ReminderView
from pyicloud.domain import ReminderDTO, ReminderListsDTO


def map_reminder(view: ReminderView) -> ReminderDTO:
    return dict(view.payload)


def map_reminder_collections(views: Sequence[ReminderCollectionView]) -> ReminderListsDTO:
    return {view.title: [map_reminder(item) for item in view.reminders] for view in views}
