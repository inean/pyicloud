"""Legacy-backed adapter for contacts domain operations."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from pyicloud.ports import ContactsServicePort

from .runtime import LegacyServicesAdapterBase


class ContactsServiceAdapter(LegacyServicesAdapterBase, ContactsServicePort):
    """Map contacts operations to the contacts service port contract."""

    def all_contacts(self, *, username: str) -> Sequence[Mapping[str, Any]]:
        contacts = self._services(username=username).contacts.all() or []
        return [dict(item) for item in contacts]
