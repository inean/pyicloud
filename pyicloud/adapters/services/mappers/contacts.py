"""Domain mappers for typed contacts client views."""

from __future__ import annotations

from pyicloud.adapters.services.clients.contacts import ContactView
from pyicloud.domain import ContactDTO


def map_contact(view: ContactView) -> ContactDTO:
    return dict(view.payload)
