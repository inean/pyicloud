"""Mapping helpers for typed service client views."""

from .account import map_account_device, map_account_family_member, map_account_storage
from .calendar import map_calendar, map_calendar_event, map_calendar_event_detail
from .contacts import map_contact
from .devices import map_device_location, map_device_snapshot, map_device_status
from .drive import map_drive_node
from .photos import map_photo_album, map_photo_asset, map_photo_version
from .reminders import map_reminder, map_reminder_collections
from .ubiquity import map_ubiquity_node

__all__ = [
    "map_account_device",
    "map_account_family_member",
    "map_account_storage",
    "map_calendar",
    "map_calendar_event",
    "map_calendar_event_detail",
    "map_contact",
    "map_device_location",
    "map_device_snapshot",
    "map_device_status",
    "map_drive_node",
    "map_photo_album",
    "map_photo_asset",
    "map_photo_version",
    "map_reminder",
    "map_reminder_collections",
    "map_ubiquity_node",
]
