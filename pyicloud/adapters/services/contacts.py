"""Legacy-backed adapter for contacts domain operations."""

from __future__ import annotations

from collections.abc import Sequence

from pyicloud.domain import ContactDTO
from pyicloud.ports import ContactsServicePort

from .clients.contacts import ContactsClient, LegacyContactsClient
from .mappers.contacts import map_contact
from .runtime import ServicesAdapterBase


class ContactsServiceAdapter(ServicesAdapterBase, ContactsServicePort):
    """Map contacts operations to the contacts service port contract."""

    def _contacts_client(self, *, username: str) -> ContactsClient:
        return LegacyContactsClient(runtime=self._runtime, username=username)

    async def all_contacts(self, *, username: str) -> Sequence[ContactDTO]:
        views = await self._run_blocking(lambda: self._contacts_client(username=username).all_contacts())
        return [map_contact(view) for view in views]
