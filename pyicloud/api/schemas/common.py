"""Common API response envelope schemas."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class DataEnvelope(BaseModel):
    data: Any


class ApiErrorDetail(BaseModel):
    code: str
    message: str
    status: int
    details: Any | None = None


class ErrorEnvelope(BaseModel):
    error: ApiErrorDetail
