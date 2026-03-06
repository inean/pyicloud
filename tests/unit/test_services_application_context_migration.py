"""Checks for services application decomposition into context-scoped services."""

from __future__ import annotations

from typing import cast

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
