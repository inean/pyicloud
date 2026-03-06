"""Reminder request schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class ReminderCreateRequest(BaseModel):
    title: str = Field(min_length=1)
    description: str = ""
    collection: str | None = None
    due_date: datetime | None = None
