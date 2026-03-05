"""Legacy-backed adapter for contacts domain operations."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from pyicloud.ports import ContactsServicePort

from .clients.contacts import ContactsClient, LegacyContactsClient
from .mappers.contacts import map_contact
from .runtime import LegacyServicesAdapterBase


class ContactsServiceAdapter(LegacyServicesAdapterBase, ContactsServicePort):
    """Map contacts operations to the contacts service port contract."""

    def _contacts_client(self, *, username: str) -> ContactsClient:
        return LegacyContactsClient(runtime=self._runtime, username=username)

    def all_contacts(self, *, username: str) -> Sequence[Mapping[str, Any]]:
        return [map_contact(view) for view in self._contacts_client(username=username).all_contacts()]
