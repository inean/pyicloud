from __future__ import annotations

from abc import ABC
from typing import Annotated, Any, Callable, ClassVar, Self, cast

import httpx
from pydantic import ConfigDict, PrivateAttr, ValidationInfo, model_validator

from pyicloud.constants import AppleHeaders as Header
from pyicloud.constants import iCloud
from pyicloud.models.settings import Settings
from pyicloud.models.types import LeafModel, Meta, MetaFields


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


class OAuthHeadersModel(HeadersModel):
    oauth_client_id: Annotated[str, Meta(header=Header.OAUTH_CLIENT_ID)] = iCloud.WIDGET_KEY
    oauth_client_type: Annotated[str, Meta(header=Header.OAUTH_CLIENT_TYPE)] = iCloud.CLIENT_TYPE
    oauth_redirect_uri: Annotated[str, Meta(header=Header.OAUTH_REDIRECT_URI)] = iCloud.REDIRECT_URI
    oauth_require_grant_code: Annotated[str, Meta(header=Header.OAUTH_REQUIRE_GRANT_CODE)] = iCloud.REQUIRE_GRANT_CODE
    oauth_response_mode: Annotated[str, Meta(header=Header.OAUTH_RESPONSE_MODE)] = iCloud.RESPONSE_MODE
    oauth_response_type: Annotated[str, Meta(header=Header.OAUTH_RESPONSE_TYPE)] = iCloud.RESPONSE_TYPE
    oauth_state: Annotated[str, Meta(header=Header.OAUTH_STATE, config="client_settings.client_id")] = cast(Any, None)
    widget_key: Annotated[str, Meta(header=Header.WIDGET_KEY)] = iCloud.WIDGET_KEY
