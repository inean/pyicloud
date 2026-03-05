"""Domain mappers for typed device client views."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pyicloud.adapters.services.clients.devices import DeviceLocationView, DeviceSnapshot, DeviceStatusView


def map_device_snapshot(view: DeviceSnapshot) -> Mapping[str, Any]:
    return dict(view.payload)


def map_device_location(view: DeviceLocationView) -> Mapping[str, Any]:
    return dict(view.payload)


def map_device_status(view: DeviceStatusView) -> Mapping[str, Any]:
    return {
        "id": view.device_id,
        "name": view.name,
        "deviceClass": view.device_class,
        "batteryLevel": view.battery_level,
        "batteryStatus": view.battery_status,
    }
