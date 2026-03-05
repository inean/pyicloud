"""Domain mappers for typed contacts client views."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pyicloud.adapters.services.clients.contacts import ContactView


def map_contact(view: ContactView) -> Mapping[str, Any]:
    return dict(view.payload)
