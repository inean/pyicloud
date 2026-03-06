"""Compatibility shim for service ports moved to semantic contexts."""

from pyicloud.contexts.services.contracts.services import (
    AccountServicePort,
    CalendarServicePort,
    ContactsServicePort,
    DeviceServicePort,
    DriveServicePort,
    PhotosServicePort,
    RemindersServicePort,
    UbiquityServicePort,
)

__all__ = [
    "AccountServicePort",
    "CalendarServicePort",
    "ContactsServicePort",
    "DeviceServicePort",
    "DriveServicePort",
    "PhotosServicePort",
    "RemindersServicePort",
    "UbiquityServicePort",
]
