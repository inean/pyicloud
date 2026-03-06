"""Typed client for legacy contacts operations."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from pyicloud.adapters.services.clients.common import Pagination
from pyicloud.platform.provider.runtime import ServiceRuntime


@dataclass(frozen=True)
class ContactView:
    payload: Mapping[str, Any]


class ContactsClient(Protocol):
    def all_contacts(self, *, pagination: Pagination | None = None) -> Sequence[ContactView]: ...


class LegacyContactsClient:
    """Query contacts data from legacy service objects with typed views."""

    def __init__(self, *, runtime: ServiceRuntime, username: str):
        self._runtime = runtime
        self._username = username

    def all_contacts(self, *, pagination: Pagination | None = None) -> Sequence[ContactView]:
        contacts = [dict(item) for item in (self._runtime.services(username=self._username).contacts.all() or [])]
        if pagination is not None:
            start = max(0, pagination.offset)
            end = start + max(0, pagination.limit)
            contacts = contacts[start:end]
        return [ContactView(payload=item) for item in contacts]
