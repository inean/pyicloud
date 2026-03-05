"""Core service adapter implementations."""

from .account import AccountServiceAdapter
from .calendar import CalendarServiceAdapter
from .composition import CoreAdapterBundle, build_core_adapter_bundle
from .contacts import ContactsServiceAdapter
from .devices import DevicesServiceAdapter
from .drive import DriveServiceAdapter
from .legacy_core import LegacyCoreServicesAdapter
from .photos import PhotosServiceAdapter
from .reminders import RemindersServiceAdapter
from .runtime import ServiceRuntime
from .ubiquity import UbiquityServiceAdapter

__all__ = [
    "AccountServiceAdapter",
    "CalendarServiceAdapter",
    "ContactsServiceAdapter",
    "DevicesServiceAdapter",
    "DriveServiceAdapter",
    "CoreAdapterBundle",
    "LegacyCoreServicesAdapter",
    "ServiceRuntime",
    "PhotosServiceAdapter",
    "RemindersServiceAdapter",
    "UbiquityServiceAdapter",
    "build_core_adapter_bundle",
]
