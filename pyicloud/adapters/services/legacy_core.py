"""Compatibility facade over decomposed legacy-backed domain adapters."""

from __future__ import annotations

from pyicloud.ports import ServiceEndpointPort, SessionStorePort

from .account import AccountServiceAdapter
from .calendar import CalendarServiceAdapter
from .contacts import ContactsServiceAdapter
from .devices import DevicesServiceAdapter
from .drive import DriveServiceAdapter
from .photos import PhotosServiceAdapter
from .reminders import RemindersServiceAdapter
from .runtime import ServiceRuntime
from .ubiquity import UbiquityServiceAdapter


class LegacyCoreServicesAdapter(
    DevicesServiceAdapter,
    AccountServiceAdapter,
    DriveServiceAdapter,
    CalendarServiceAdapter,
    ContactsServiceAdapter,
    RemindersServiceAdapter,
    PhotosServiceAdapter,
    UbiquityServiceAdapter,
):
    """Use existing service classes as adapters behind new API-facing ports."""

    def __init__(
        self,
        *,
        session_store: SessionStorePort | None = None,
        endpoint_factory: ServiceEndpointPort | None = None,
    ):
        runtime = ServiceRuntime(
            session_store=session_store,
            endpoint_factory=endpoint_factory,
        )
        super().__init__(runtime=runtime)
