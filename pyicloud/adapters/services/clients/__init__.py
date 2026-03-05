"""Typed outbound clients for legacy-backed high-traffic domains."""

from .account import AccountClient, AccountDeviceView, AccountStorageView, LegacyAccountClient
from .devices import (
    DeviceLocationView,
    DevicesClient,
    DeviceSnapshot,
    DeviceStatusView,
    LegacyDevicesClient,
)
from .drive import DriveClient, DriveNodeView, LegacyDriveClient

__all__ = [
    "AccountClient",
    "AccountDeviceView",
    "AccountStorageView",
    "DeviceLocationView",
    "DeviceSnapshot",
    "DeviceStatusView",
    "DevicesClient",
    "DriveClient",
    "DriveNodeView",
    "LegacyAccountClient",
    "LegacyDevicesClient",
    "LegacyDriveClient",
]
