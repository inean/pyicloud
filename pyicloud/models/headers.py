from __future__ import annotations

from abc import ABC
from typing import Any, Iterator, Mapping, Tuple, cast

import httpx
from pydantic import BaseModel, Field, model_validator
from pydantic.fields import FieldInfo

from pyicloud.models.types import (
    Meta,
    RequestIdType,
)


class HeadersModel(BaseModel, ABC):
    """Result response."""

    # Add Headers as metadata so we can map them to the response
    request_id: RequestIdType = Field(default=...)

    # Catch all for json response
    response: dict[str, Any] | str | None = None

    def header_items(self) -> Iterator[Tuple[str, str, Any]]:
        # Parse httpx.Headers. Try to match available headers to the ones in fields and yield data
        for field, info in self.model_fields.items():
            if not (metadata := info.metadata):
                try:
                    metadata = cast(Any, info.annotation).__args__[0].__metadata__
                except AttributeError:
                    metadata = []
            # Get header metadata entry from field info. If exists, check if it is in
            # data and yield data with alias and value
            if meta := next((x for x in metadata if isinstance(x, Meta)), None):
                assert meta.header is not None, "Header metadata must have a header attribute"
                yield field, cast(str, meta.header), getattr(self, field)

    @model_validator(mode="before")
    @classmethod
    def check_headers(cls, headers: httpx.Headers) -> Any:
        data: dict[str, str | bytes | list] = {}

        # Parse httpx.Headers. Try to math available headers to the ones in fields and return data
        for field, info in cls.model_fields.items():
            if not (metadata := info.metadata):
                try:
                    metadata = cast(Any, info.annotation).__args__[0].__metadata__
                except AttributeError:
                    metadata = []
            # Get header metadata entry from field info. If exists, check if it is in
            # data and update data with alias and value
            if meta := next((x for x in metadata if isinstance(x, Meta)), None):
                if meta.header in headers:
                    values = [value for header, value in headers.multi_items() if meta.header == header]
                    data[field] = values[0] if len(values) == 1 else values
        return data

    def __contains__(self, item: str) -> bool:
        item = item.lower()
        for _, header, _ in self.header_items():
            if item == header.lower():
                return True
        return cast(HeadersModel, super()).__contains__(item)
