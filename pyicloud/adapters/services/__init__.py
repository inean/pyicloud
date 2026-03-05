"""Core service adapter implementations."""

from .account import AccountServiceAdapter
from .calendar import CalendarServiceAdapter
from .composition import LegacyCoreAdapterBundle, build_legacy_core_adapter_bundle
from .contacts import ContactsServiceAdapter
from .devices import DevicesServiceAdapter
from .drive import DriveServiceAdapter
from .legacy_core import LegacyCoreServicesAdapter
from .photos import PhotosServiceAdapter
from .reminders import RemindersServiceAdapter
from .runtime import LegacyServicesRuntime
from .ubiquity import UbiquityServiceAdapter

__all__ = [
    "AccountServiceAdapter",
    "CalendarServiceAdapter",
    "ContactsServiceAdapter",
    "DevicesServiceAdapter",
    "DriveServiceAdapter",
    "LegacyCoreAdapterBundle",
    "LegacyCoreServicesAdapter",
    "LegacyServicesRuntime",
    "PhotosServiceAdapter",
    "RemindersServiceAdapter",
    "UbiquityServiceAdapter",
    "build_legacy_core_adapter_bundle",
]
