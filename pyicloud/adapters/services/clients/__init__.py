"""Typed outbound clients for legacy-backed high-traffic domains."""

from .account import AccountClient, AccountDeviceView, AccountStorageView, LegacyAccountClient
from .calendar import (
    CalendarClient,
    CalendarEventDetailView,
    CalendarEventView,
    CalendarView,
    LegacyCalendarClient,
)
from .common import Pagination, TimeRangeFilter
from .contacts import ContactsClient, ContactView, LegacyContactsClient
from .devices import (
    DeviceLocationView,
    DevicesClient,
    DeviceSnapshot,
    DeviceStatusView,
    LegacyDevicesClient,
)
from .drive import DriveClient, DriveNodeView, LegacyDriveClient
from .photos import (
    LegacyPhotosClient,
    PhotoAlbumView,
    PhotoAssetView,
    PhotosClient,
    PhotoVersionView,
)
from .reminders import (
    LegacyRemindersClient,
    ReminderCollectionView,
    RemindersClient,
    ReminderView,
)
from .ubiquity import LegacyUbiquityClient, UbiquityClient, UbiquityNodeView

__all__ = [
    "AccountClient",
    "AccountDeviceView",
    "AccountStorageView",
    "CalendarClient",
    "CalendarEventDetailView",
    "CalendarEventView",
    "CalendarView",
    "ContactView",
    "ContactsClient",
    "DeviceLocationView",
    "DeviceSnapshot",
    "DeviceStatusView",
    "DevicesClient",
    "DriveClient",
    "DriveNodeView",
    "LegacyCalendarClient",
    "LegacyAccountClient",
    "LegacyContactsClient",
    "LegacyDevicesClient",
    "LegacyDriveClient",
    "LegacyPhotosClient",
    "LegacyRemindersClient",
    "LegacyUbiquityClient",
    "Pagination",
    "PhotoAlbumView",
    "PhotoAssetView",
    "PhotoVersionView",
    "PhotosClient",
    "ReminderCollectionView",
    "ReminderView",
    "RemindersClient",
    "TimeRangeFilter",
    "UbiquityClient",
    "UbiquityNodeView",
]
