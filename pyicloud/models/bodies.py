import re
from abc import ABC
from typing import Any, Callable, ClassVar, Self

from pydantic import (
    ConfigDict,
    ValidationInfo,
    model_validator,
)
from pydantic.alias_generators import to_camel

from pyicloud.models import LeafModel, MetaFields
from pyicloud.models.settings import Settings
from pyicloud.utils import mapping


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


class DynamicBodyModel(BodyModel):
    pattern_1: ClassVar[re.Pattern] = re.compile(r"(.)([A-Z][a-z]+)")
    pattern_2: ClassVar[re.Pattern] = re.compile("([a-z0-9])([A-Z])")

    model_config = ConfigDict(
        extra="allow",
        populate_by_name=True,
        alias_generator=to_camel,
    )

    @model_validator(mode="before")
    def make_it_all_snake_case(cls, values: dict) -> dict:
        snake_values = mapping.map(values, cls.camel_case_or_pascal_case_to_snake_case)
        return snake_values

    @classmethod
    def camel_case_or_pascal_case_to_snake_case(cls, camel_case_string: str) -> str:
        """Converts a camelCase or PascalCase string to snake_case."""
        string = cls.pattern_1.sub(r"\1_\2", camel_case_string)
        string = cls.pattern_2.sub(r"\1_\2", string).lower()
        return string
