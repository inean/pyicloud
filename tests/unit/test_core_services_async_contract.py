from __future__ import annotations

import asyncio
import inspect
from typing import Any, cast

import pytest

from pyicloud.adapters.services import (
    AccountServiceAdapter,
    CalendarServiceAdapter,
    ContactsServiceAdapter,
    DevicesServiceAdapter,
    DriveServiceAdapter,
    PhotosServiceAdapter,
    RemindersServiceAdapter,
    UbiquityServiceAdapter,
)
from pyicloud.application.core_services import CoreServicesApi
from pyicloud.ports import (
    AccountServicePort,
    CalendarServicePort,
    ContactsServicePort,
    DeviceServicePort,
    DriveServicePort,
    PhotosServicePort,
    RemindersServicePort,
    UbiquityServicePort,
)


def _protocol_async_method_names(protocol: type[Any]) -> set[str]:
    names: set[str] = set()
    for name, value in protocol.__dict__.items():
        if name.startswith("_"):
            continue
        if inspect.iscoroutinefunction(value):
            names.add(name)
    return names


@pytest.mark.parametrize(
    ("adapter_cls", "protocol"),
    [
        (DevicesServiceAdapter, DeviceServicePort),
        (AccountServiceAdapter, AccountServicePort),
        (DriveServiceAdapter, DriveServicePort),
        (CalendarServiceAdapter, CalendarServicePort),
        (ContactsServiceAdapter, ContactsServicePort),
        (RemindersServiceAdapter, RemindersServicePort),
        (PhotosServiceAdapter, PhotosServicePort),
        (UbiquityServiceAdapter, UbiquityServicePort),
    ],
)
def test_service_adapters_match_async_port_methods(adapter_cls: type[Any], protocol: type[Any]) -> None:
    for method_name in _protocol_async_method_names(protocol):
        method = getattr(adapter_cls, method_name, None)
        assert method is not None, f"{adapter_cls.__name__} is missing method {method_name}"
        assert inspect.iscoroutinefunction(
            method
        ), f"{adapter_cls.__name__}.{method_name} must be async to satisfy {protocol.__name__}"


def _build_core_services_api_with_devices(devices: Any) -> CoreServicesApi:
    return CoreServicesApi(
        devices=cast(DeviceServicePort, devices),
        accounts=cast(AccountServicePort, object()),
        drive=cast(DriveServicePort, object()),
        calendars=cast(CalendarServicePort, object()),
        contacts=cast(ContactsServicePort, object()),
        reminders=cast(RemindersServicePort, object()),
        photos=cast(PhotosServicePort, object()),
        ubiquity=cast(UbiquityServicePort, object()),
    )


class _SyncDevicesPort:
    def list_devices(self, *, username: str):  # noqa: ARG002
        return []


class _DelayedDevicesPort:
    def __init__(self) -> None:
        self.cancelled = False

    async def list_devices(self, *, username: str):  # noqa: ARG002
        try:
            await asyncio.sleep(1.0)
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        return []


@pytest.mark.asyncio
async def test_core_services_api_requires_async_device_port_methods() -> None:
    api = _build_core_services_api_with_devices(_SyncDevicesPort())

    with pytest.raises(TypeError, match="can't be used in 'await' expression"):
        await api.list_devices(username="user@example.com")


@pytest.mark.asyncio
async def test_core_services_api_propagates_cancellation_on_timeout() -> None:
    delayed = _DelayedDevicesPort()
    api = _build_core_services_api_with_devices(delayed)

    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(api.list_devices(username="user@example.com"), timeout=0.01)

    assert delayed.cancelled is True
