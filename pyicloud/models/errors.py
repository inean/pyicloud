from __future__ import annotations

from typing import Any, Callable, Generic, Self, TypeVar

from pydantic import AliasChoices, BaseModel, Field, ValidationInfo, model_validator

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
