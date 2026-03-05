"""Legacy-backed adapter for device domain operations."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from pyicloud.ports import DeviceServicePort

from .runtime import LegacyServicesAdapterBase


class DevicesServiceAdapter(LegacyServicesAdapterBase, DeviceServicePort):
    """Map Find My iPhone operations to the device service port contract."""

    @staticmethod
    def _iter_devices(manager: Any) -> list[Any]:
        try:
            keys = list(manager.keys())
            return [manager[key] for key in keys]
        except Exception:  # noqa: BLE001
            pass

        devices = []
        idx = 0
        while True:
            try:
                devices.append(manager[idx])
                idx += 1
            except Exception:  # noqa: BLE001
                break
        return devices

    def _get_device(self, *, username: str, device_id: str) -> Any:
        manager = self._services(username=username).devices
        for device in self._iter_devices(manager):
            if str(device["id"]) == device_id:
                return device
        raise KeyError(f"Device not found: {device_id}")

    def list_devices(self, *, username: str) -> Sequence[Mapping[str, Any]]:
        manager = self._services(username=username).devices
        return [dict(device.data) for device in self._iter_devices(manager)]

    def location(self, *, username: str, device_id: str) -> Mapping[str, Any]:
        device = self._get_device(username=username, device_id=device_id)
        location = device.location()
        if isinstance(location, dict):
            return location
        return {"location": location}

    def status(self, *, username: str, device_id: str) -> Mapping[str, Any]:
        return dict(self._get_device(username=username, device_id=device_id).status())

    def play_sound(self, *, username: str, device_id: str, subject: str) -> None:
        self._get_device(username=username, device_id=device_id).play_sound(subject=subject)

    def display_message(self, *, username: str, device_id: str, subject: str, message: str, sounds: bool) -> None:
        self._get_device(username=username, device_id=device_id).display_message(
            subject=subject,
            message=message,
            sounds=sounds,
        )

    def lost_mode(
        self,
        *,
        username: str,
        device_id: str,
        number: str,
        text: str,
        newpasscode: str,
    ) -> None:
        self._get_device(username=username, device_id=device_id).lost_device(
            number=number,
            text=text,
            newpasscode=newpasscode,
        )
