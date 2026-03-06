"""Composition helpers for domain adapters."""

from __future__ import annotations

from dataclasses import dataclass

from pyicloud.contexts.services.account.adapters import AccountServiceAdapter
from pyicloud.contexts.services.calendar.adapters import CalendarServiceAdapter
from pyicloud.contexts.services.contacts.adapters import ContactsServiceAdapter
from pyicloud.contexts.services.devices.adapters import DevicesServiceAdapter
from pyicloud.contexts.services.drive.adapters import DriveServiceAdapter
from pyicloud.contexts.services.photos.adapters import PhotosServiceAdapter
from pyicloud.contexts.services.reminders.adapters import RemindersServiceAdapter
from pyicloud.contexts.services.ubiquity.adapters import UbiquityServiceAdapter
from pyicloud.platform.provider.runtime import ServiceRuntime
from pyicloud.ports import (
    AccountServicePort,
    CalendarServicePort,
    ContactsServicePort,
    DeviceServicePort,
    DriveServicePort,
    PhotosServicePort,
    RemindersServicePort,
    ServiceEndpointPort,
    SessionStorePort,
    UbiquityServicePort,
)


@dataclass(frozen=True)
class CoreAdapterBundle:
    devices: DeviceServicePort
    accounts: AccountServicePort
    drive: DriveServicePort
    calendars: CalendarServicePort
    contacts: ContactsServicePort
    reminders: RemindersServicePort
    photos: PhotosServicePort
    ubiquity: UbiquityServicePort


def build_core_adapter_bundle(
    *,
    session_store: SessionStorePort | None = None,
    endpoint_factory: ServiceEndpointPort | None = None,
) -> CoreAdapterBundle:
    """Build per-domain adapters backed by one shared runtime."""

    runtime = ServiceRuntime(
        session_store=session_store,
        endpoint_factory=endpoint_factory,
    )
    return CoreAdapterBundle(
        devices=DevicesServiceAdapter(runtime=runtime),
        accounts=AccountServiceAdapter(runtime=runtime),
        drive=DriveServiceAdapter(runtime=runtime),
        calendars=CalendarServiceAdapter(runtime=runtime),
        contacts=ContactsServiceAdapter(runtime=runtime),
        reminders=RemindersServiceAdapter(runtime=runtime),
        photos=PhotosServiceAdapter(runtime=runtime),
        ubiquity=UbiquityServiceAdapter(runtime=runtime),
    )
