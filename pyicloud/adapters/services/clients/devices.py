"""Typed client for legacy Find My iPhone device operations."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from pyicloud.platform.provider.runtime import ServiceRuntime


@dataclass(frozen=True)
class DeviceSnapshot:
    device_id: str
    payload: Mapping[str, Any]


@dataclass(frozen=True)
class DeviceLocationView:
    payload: Mapping[str, Any]


@dataclass(frozen=True)
class DeviceStatusView:
    device_id: str
    name: str | None
    device_class: str | None
    battery_level: float | int | None
    battery_status: str | None


class DevicesClient(Protocol):
    def list_devices(self) -> Sequence[DeviceSnapshot]: ...
    def location(self, *, device_id: str) -> DeviceLocationView: ...
    def status(self, *, device_id: str) -> DeviceStatusView: ...
    def play_sound(self, *, device_id: str, subject: str) -> None: ...
    def display_message(self, *, device_id: str, subject: str, message: str, sounds: bool) -> None: ...
    def lost_mode(self, *, device_id: str, number: str, text: str, newpasscode: str) -> None: ...


class LegacyDevicesClient:
    """Query/mutate devices using legacy service objects behind typed models."""

    def __init__(self, *, runtime: ServiceRuntime, username: str):
        self._runtime = runtime
        self._username = username

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

    def _device(self, *, device_id: str) -> Any:
        manager = self._runtime.services(username=self._username).devices
        for device in self._iter_devices(manager):
            if str(device["id"]) == device_id:
                return device
        raise KeyError(f"Device not found: {device_id}")

    def list_devices(self) -> Sequence[DeviceSnapshot]:
        manager = self._runtime.services(username=self._username).devices
        snapshots: list[DeviceSnapshot] = []
        for device in self._iter_devices(manager):
            payload = dict(device.data)
            snapshots.append(DeviceSnapshot(device_id=str(payload.get("id", "")), payload=payload))
        return snapshots

    def location(self, *, device_id: str) -> DeviceLocationView:
        location = self._device(device_id=device_id).location()
        if isinstance(location, dict):
            return DeviceLocationView(payload=location)
        return DeviceLocationView(payload={"location": location})

    def status(self, *, device_id: str) -> DeviceStatusView:
        status = dict(self._device(device_id=device_id).status())
        return DeviceStatusView(
            device_id=device_id,
            name=str(status.get("name")) if status.get("name") is not None else None,
            device_class=str(status.get("deviceClass")) if status.get("deviceClass") is not None else None,
            battery_level=status.get("batteryLevel"),
            battery_status=str(status.get("batteryStatus")) if status.get("batteryStatus") is not None else None,
        )

    def play_sound(self, *, device_id: str, subject: str) -> None:
        self._device(device_id=device_id).play_sound(subject=subject)

    def display_message(self, *, device_id: str, subject: str, message: str, sounds: bool) -> None:
        self._device(device_id=device_id).display_message(
            subject=subject,
            message=message,
            sounds=sounds,
        )

    def lost_mode(self, *, device_id: str, number: str, text: str, newpasscode: str) -> None:
        self._device(device_id=device_id).lost_device(
            number=number,
            text=text,
            newpasscode=newpasscode,
        )
