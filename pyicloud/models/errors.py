from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import AliasChoices, BaseModel, Field

E = TypeVar("E", bound="Error")


class Error(BaseModel):
    code: int
    title: str | None = None
    message: str
    suppress_dimissal: bool = Field(
        default=False,
        validation_alias=AliasChoices("suppressDismissal"),
    )


class ServiceErrorsModel(BaseModel, Generic[E]):
    service_errors: list[E] = Field(
        default=[],
        validation_alias=AliasChoices("serviceErrors", "service_errors"),
    )
    has_error: bool = Field(
        default=True,
        validation_alias=AliasChoices("hasError"),
    )
