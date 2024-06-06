from abc import ABC
from typing import Any, Callable, Self

from pydantic import (
    ConfigDict,
    ValidationInfo,
    model_validator,
)

from pyicloud.models.settings import Settings
from pyicloud.models.types import LeafModel, MetaFields


class BodyModel(LeafModel, ABC):
    model_config = ConfigDict(extra="allow")

    @model_validator(mode="wrap")
    @classmethod
    def model_validate_from_settings(cls, data: dict[str, Any], handler: Callable, info: ValidationInfo) -> Self:
        settings: Settings | None = None

        if isinstance(data, cls):
            return handler(data)

        assert isinstance(data, dict), f"Invalid data type for '{cls}': {type(data)}"

        if isinstance(info.context, dict):
            settings = info.context.get("settings", None)

            if isinstance(settings, Settings):
                by_meta: MetaFields = info.context.get("by_meta", "config")
                for field, meta_config, _ in cls.model_fields_from_meta(by_meta=by_meta):
                    data.setdefault(field, settings[meta_config])

        return handler(data)

    @property
    def json_data(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, context=dict(by_meta="body"))

    @property
    def content(self) -> None:
        return None


class EmptyModel(BodyModel):
    model_config = ConfigDict(extra="forbid")

    @classmethod
    def model_validate_json(
        cls,
        json_data: str | bytes | bytearray,
        *,
        strict: bool | None = None,
        context: dict[str, Any] | None = None,
    ) -> Self:
        return cls()

    @property
    def json_data(self) -> None:
        return None

    @property
    def content(self) -> bytes:
        return b""
