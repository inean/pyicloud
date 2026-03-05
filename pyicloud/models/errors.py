from __future__ import annotations

from collections.abc import Callable
from typing import Any, Self

from pydantic import AliasChoices, BaseModel, Field, ValidationInfo, field_validator, model_validator


class Error(BaseModel):
    code: int
    title: str | None = None
    message: str
    suppress_dimissal: bool = Field(
        default=False,
        validation_alias=AliasChoices("suppressDismissal"),
    )

    @field_validator("message", mode="before")
    @classmethod
    def coerce_message(cls, value: Any) -> str:
        if isinstance(value, str):
            return value
        if value is None:
            return ""
        return str(value)


class ServiceErrorsModel[E: Error](BaseModel):
    service_errors: list[E] = Field(
        default=[],
        validation_alias=AliasChoices("serviceErrors", "service_errors"),
    )
    has_error: bool = Field(
        default=True,
        validation_alias=AliasChoices("hasError"),
    )

    @model_validator(mode="wrap")
    @classmethod
    def model_validate_from_response(cls, data: dict[str, Any], handler: Callable, info: ValidationInfo) -> Self:
        """Create a response from a httpx response."""
        if "success" in data:
            data = {
                "service_errors": [
                    {
                        "code": 0,
                        "message": data["error"],
                    },
                ],
                "has_error": data["success"],
            }
        return handler(data)
