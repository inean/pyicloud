"""Domain mappers for typed device client views."""

from __future__ import annotations

from pyicloud.adapters.services.clients.devices import DeviceLocationView, DeviceSnapshot, DeviceStatusView
from pyicloud.domain import DeviceRecordDTO


def map_device_snapshot(view: DeviceSnapshot) -> DeviceRecordDTO:
    return dict(view.payload)


def map_device_location(view: DeviceLocationView) -> DeviceRecordDTO:
    return dict(view.payload)


def map_device_status(view: DeviceStatusView) -> DeviceRecordDTO:
    return {
        "id": view.device_id,
        "name": view.name,
        "deviceClass": view.device_class,
        "batteryLevel": view.battery_level,
        "batteryStatus": view.battery_status,
    }
