"""Checks for services application decomposition into context-scoped services."""

from __future__ import annotations

import importlib
from typing import cast

import pyicloud.adapters.services.composition as services_composition
from pyicloud.application.core_services import CoreServicesApi
from pyicloud.contexts.services.contracts.services import (
    AccountServicePort,
    CalendarServicePort,
    ContactsServicePort,
    DeviceServicePort,
    DriveServicePort,
    PhotosServicePort,
    RemindersServicePort,
    UbiquityServicePort,
)


def test_core_services_api_delegates_to_context_application_services() -> None:
    api = CoreServicesApi(
        devices=cast(DeviceServicePort, object()),
        accounts=cast(AccountServicePort, object()),
        drive=cast(DriveServicePort, object()),
        calendars=cast(CalendarServicePort, object()),
        contacts=cast(ContactsServicePort, object()),
        reminders=cast(RemindersServicePort, object()),
        photos=cast(PhotosServicePort, object()),
        ubiquity=cast(UbiquityServicePort, object()),
    )

    assert api._devices.__class__.__module__.startswith("pyicloud.contexts.services.devices.application.")
    assert api._account.__class__.__module__.startswith("pyicloud.contexts.services.account.application.")
    assert api._drive.__class__.__module__.startswith("pyicloud.contexts.services.drive.application.")
    assert api._calendar.__class__.__module__.startswith("pyicloud.contexts.services.calendar.application.")
    assert api._contacts.__class__.__module__.startswith("pyicloud.contexts.services.contacts.application.")
    assert api._reminders.__class__.__module__.startswith("pyicloud.contexts.services.reminders.application.")
    assert api._photos.__class__.__module__.startswith("pyicloud.contexts.services.photos.application.")
    assert api._ubiquity.__class__.__module__.startswith("pyicloud.contexts.services.ubiquity.application.")


def test_core_adapter_composition_uses_context_service_adapters() -> None:
    assert services_composition.AccountServiceAdapter.__module__.startswith(
        "pyicloud.contexts.services.account.adapters."
    )
    assert services_composition.CalendarServiceAdapter.__module__.startswith(
        "pyicloud.contexts.services.calendar.adapters."
    )
    assert services_composition.ContactsServiceAdapter.__module__.startswith(
        "pyicloud.contexts.services.contacts.adapters."
    )
    assert services_composition.DevicesServiceAdapter.__module__.startswith(
        "pyicloud.contexts.services.devices.adapters."
    )
    assert services_composition.DriveServiceAdapter.__module__.startswith("pyicloud.contexts.services.drive.adapters.")
    assert services_composition.RemindersServiceAdapter.__module__.startswith(
        "pyicloud.contexts.services.reminders.adapters."
    )
    assert services_composition.PhotosServiceAdapter.__module__.startswith(
        "pyicloud.contexts.services.photos.adapters."
    )
    assert services_composition.UbiquityServiceAdapter.__module__.startswith(
        "pyicloud.contexts.services.ubiquity.adapters."
    )


def test_services_adapter_shims_reexport_context_adapters() -> None:
    pairs = [
        (
            "pyicloud.adapters.services.account",
            "pyicloud.contexts.services.account.adapters.service",
            "AccountServiceAdapter",
        ),
        (
            "pyicloud.adapters.services.calendar",
            "pyicloud.contexts.services.calendar.adapters.service",
            "CalendarServiceAdapter",
        ),
        (
            "pyicloud.adapters.services.contacts",
            "pyicloud.contexts.services.contacts.adapters.service",
            "ContactsServiceAdapter",
        ),
        (
            "pyicloud.adapters.services.devices",
            "pyicloud.contexts.services.devices.adapters.service",
            "DevicesServiceAdapter",
        ),
        (
            "pyicloud.adapters.services.drive",
            "pyicloud.contexts.services.drive.adapters.service",
            "DriveServiceAdapter",
        ),
        (
            "pyicloud.adapters.services.reminders",
            "pyicloud.contexts.services.reminders.adapters.service",
            "RemindersServiceAdapter",
        ),
        (
            "pyicloud.adapters.services.photos",
            "pyicloud.contexts.services.photos.adapters.service",
            "PhotosServiceAdapter",
        ),
        (
            "pyicloud.adapters.services.ubiquity",
            "pyicloud.contexts.services.ubiquity.adapters.service",
            "UbiquityServiceAdapter",
        ),
    ]
    for legacy_module_name, canonical_module_name, symbol in pairs:
        legacy_module = importlib.import_module(legacy_module_name)
        canonical_module = importlib.import_module(canonical_module_name)
        assert getattr(legacy_module, symbol) is getattr(canonical_module, symbol)
