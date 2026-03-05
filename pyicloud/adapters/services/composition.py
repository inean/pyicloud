"""Composition helpers for legacy-backed domain adapters."""

from __future__ import annotations

from dataclasses import dataclass

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

from .account import AccountServiceAdapter
from .calendar import CalendarServiceAdapter
from .contacts import ContactsServiceAdapter
from .devices import DevicesServiceAdapter
from .drive import DriveServiceAdapter
from .photos import PhotosServiceAdapter
from .reminders import RemindersServiceAdapter
from .runtime import LegacyServicesRuntime
from .ubiquity import UbiquityServiceAdapter


@dataclass(frozen=True)
class LegacyCoreAdapterBundle:
    devices: DeviceServicePort
    accounts: AccountServicePort
    drive: DriveServicePort
    calendars: CalendarServicePort
    contacts: ContactsServicePort
    reminders: RemindersServicePort
    photos: PhotosServicePort
    ubiquity: UbiquityServicePort


def build_legacy_core_adapter_bundle(
    *,
    session_store: SessionStorePort | None = None,
    endpoint_factory: ServiceEndpointPort | None = None,
) -> LegacyCoreAdapterBundle:
    """Build per-domain adapters backed by one shared legacy runtime."""

    runtime = LegacyServicesRuntime(
        session_store=session_store,
        endpoint_factory=endpoint_factory,
    )
    return LegacyCoreAdapterBundle(
        devices=DevicesServiceAdapter(runtime=runtime),
        accounts=AccountServiceAdapter(runtime=runtime),
        drive=DriveServiceAdapter(runtime=runtime),
        calendars=CalendarServiceAdapter(runtime=runtime),
        contacts=ContactsServiceAdapter(runtime=runtime),
        reminders=RemindersServiceAdapter(runtime=runtime),
        photos=PhotosServiceAdapter(runtime=runtime),
        ubiquity=UbiquityServiceAdapter(runtime=runtime),
    )
