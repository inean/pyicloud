"""Shared query models for typed service clients."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class Pagination:
    limit: int = 100
    offset: int = 0


@dataclass(frozen=True)
class TimeRangeFilter:
    from_dt: datetime | None = None
    to_dt: datetime | None = None
