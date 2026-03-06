"""Compatibility exports for core service adapters."""

from pyicloud.contexts.services.account.adapters import AccountServiceAdapter
from pyicloud.contexts.services.calendar.adapters import CalendarServiceAdapter
from pyicloud.contexts.services.contacts.adapters import ContactsServiceAdapter
from pyicloud.contexts.services.devices.adapters import DevicesServiceAdapter
from pyicloud.contexts.services.drive.adapters import DriveServiceAdapter
from pyicloud.contexts.services.photos.adapters import PhotosServiceAdapter
from pyicloud.contexts.services.ubiquity.adapters import UbiquityServiceAdapter

from .composition import CoreAdapterBundle, build_core_adapter_bundle
from .legacy_core import LegacyCoreServicesAdapter
from .reminders import RemindersServiceAdapter

__all__ = [
    "AccountServiceAdapter",
    "CalendarServiceAdapter",
    "ContactsServiceAdapter",
    "DevicesServiceAdapter",
    "DriveServiceAdapter",
    "CoreAdapterBundle",
    "LegacyCoreServicesAdapter",
    "PhotosServiceAdapter",
    "RemindersServiceAdapter",
    "UbiquityServiceAdapter",
    "build_core_adapter_bundle",
]
