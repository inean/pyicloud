from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import BaseModel, Field

E = TypeVar("E", bound="Error")


class Error(BaseModel):
    code: int
    message: str


class ServiceErrorsModel(BaseModel, Generic[E]):
    service_errors: list[E] = Field(default=[], validation_alias="serviceErrors")
