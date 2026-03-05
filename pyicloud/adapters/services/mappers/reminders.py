"""Domain mappers for typed reminders client views."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from pyicloud.adapters.services.clients.reminders import ReminderCollectionView, ReminderView


def map_reminder(view: ReminderView) -> Mapping[str, Any]:
    return dict(view.payload)


def map_reminder_collections(views: Sequence[ReminderCollectionView]) -> Mapping[str, Sequence[Mapping[str, Any]]]:
    return {view.title: [map_reminder(item) for item in view.reminders] for view in views}
