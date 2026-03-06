"""Account schemas."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel


class AccountStorageResponse(BaseModel):
    usage: Mapping[str, Any]
    usages_by_media: Mapping[str, Mapping[str, Any]]
