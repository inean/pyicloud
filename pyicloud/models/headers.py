from __future__ import annotations

from abc import ABC
from typing import Any, Callable, ClassVar, Self, cast

import httpx
from pydantic import ConfigDict, PrivateAttr, ValidationInfo, model_validator

from pyicloud.models.settings import Settings
from pyicloud.models.types import LeafModel, MetaFields


class HeadersModel(LeafModel, ABC):
    """Headers"""

    model_config = ConfigDict(extra="allow")

    _by_meta: ClassVar[MetaFields] = PrivateAttr(default="header")

    @staticmethod
    def _get_value_from_header(field: str, header: Any) -> Any:
        values = [value for header, value in cast(httpx.Headers, header).multi_items() if field == header]
        return values[0] if len(values) == 1 else values

    @model_validator(mode="wrap")
    @classmethod
    def validate_headers(cls, data: dict[str, Any] | Self, handler: Callable, info: ValidationInfo) -> Self:
        headers: httpx.Headers | None = None

        if isinstance(data, cls):
            return handler(data)

        assert isinstance(data, dict), f"Invalid data type for '{cls}': {type(data)}"

        if isinstance(info.context, dict):
            headers = info.context.get("headers", None)

            # If header's is set, assume is a response header, so ignore settings and parse only headers
            #
            if isinstance(headers, httpx.Headers):
                for field, meta_header, _ in cls.model_fields_from_meta(by_meta=cls._by_meta):
                    if meta_header in headers:
                        data.setdefault(field, cls._get_value_from_header(meta_header, headers))
            elif settings := info.context.get("settings", None):
                assert isinstance(settings, Settings), "Settings must be a Settings instance"
                for field, config, _ in cls.model_fields_from_meta(by_meta="config"):
                    data.setdefault(field, settings[config])

        return handler(data)

    def __contains__(self, item: str) -> bool:
        item = item.lower()
        for _, header, _ in self.model_fields_from_meta(by_meta=self._by_meta):
            if item == header.lower():
                return True
        return cast(HeadersModel, super()).__contains__(item)
