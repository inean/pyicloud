from __future__ import annotations

from abc import ABC, abstractmethod
from functools import cached_property
from typing import Any, Generic, Self, Type, TypedDict, TypeVar, cast

import httpx
from pydantic import BaseModel, Field, model_validator
from typing_extensions import ClassVar

from pyicloud.constants import Endpoints
from pyicloud.log import PyiCloudPasswordFilter, logger_get
from pyicloud.models.cookies import Cookies, CookiesModel
from pyicloud.models.settings import (
    CountryCodeType,
    ScntType,
    SessionIdType,
    SessionTokenType,
    Settings,
    TrustTokenType,
)
from pyicloud.models.types import (
    Meta,
)


class ErrorModel(BaseModel):
    code: int
    message: str


class SettingsModel(BaseModel, ABC):
    """Update the settings with the result data."""


class HeadersModel(BaseModel, ABC):
    """Result response."""

    # Add Headers as metadata so we can map them to the response
    country_code: CountryCodeType
    trust_token: TrustTokenType | None = None
    session_token: SessionTokenType | None = None
    session_id: SessionIdType | None = None
    scnt: ScntType | None = None

    # Catch all for json response
    response: dict[str, Any] | str | None = None

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
            # Get header metadata entry from field info. If exists, check if it is in data and update data with alias and value
            if meta := next((x for x in metadata if isinstance(x, Meta)), None):
                if meta.header in headers:
                    values = [value for header, value in headers.multi_items() if meta.header == header]
                    data[field] = values[0] if len(values) == 1 else values
        return data


H = TypeVar("H", bound=HeadersModel)
C = TypeVar("C", bound=CookiesModel)


class ResponseConfig(TypedDict, total=False):
    headers: type[HeadersModel]
    cookies: type[CookiesModel]


class BaseResponse(BaseModel, Generic[H, C]):
    """Response data."""

    _config: ClassVar[ResponseConfig] = ResponseConfig(
        headers=HeadersModel,
        cookies=CookiesModel,
    )

    headers: H
    cookies: C

    status_code: int
    errors: list[ErrorModel] = Field([], alias="serviceErrors")

    # Common Headers that must be stored as config
    @classmethod
    def __pydantic_init_subclass__(cls, **kwargs):
        # Update config with default values for bae class
        new_config = ResponseConfig(
            headers=HeadersModel,
            cookies=CookiesModel,
        )
        new_config.update(cls._config)
        cls._config = new_config

    def __bool__(self):
        """Return True if the response is successful."""
        return 200 <= self.status_code < 400

    @classmethod
    def model_validate_response(cls, response: httpx.Response, *, data: Any = None) -> Self:
        """Create a response from a httpx response."""
        data = data or {}

        if response.is_error:
            if response.headers["content-type"].startswith("application/json"):
                error = ErrorModel.model_validate_json(response.content)
                data.setdefault("errors", []).append(error)

        data.setdefault("status_code", response.status_code)
        data.setdefault("headers", cls._config["headers"].model_validate(response.headers))  # type: ignore
        data.setdefault("cookies", cls._config["cookies"].model_validate(response.cookies))  # type: ignore

        # create a new instance of the response
        return cls(**data)


T = TypeVar("T", bound="BaseResponse")


class BaseSession(Generic[T], ABC):
    _cookies: Cookies
    _settings: Settings
    _httpx: httpx.AsyncClient
    _response: httpx.Response | None

    def __init__(
        self,
        settings: Settings,
        cookies: Cookies,
        client: httpx.AsyncClient | None = None,
    ):
        client = client or httpx.AsyncClient(follow_redirects=True)

        self._cookies = cookies
        self._settings = settings
        self._httpx = client
        self._response = None

        # Add a hook to response events, so last one is automatically
        # stored in self._response
        async def response_hook(value: httpx.Response) -> None:
            self._response = value
            await value.aread()

        self._httpx.event_hooks["response"].append(response_hook)

        # set password filter
        PyiCloudPasswordFilter.register(self, logger=logger_get("http"))

    async def __aenter__(self):
        # Set Cookies, if any
        self.update_headers(self._httpx.headers)
        self.update_cookies(self._httpx.cookies)
        return self._httpx

    async def __aexit__(self, exc_type, exc, tb):
        self.update_session()
        await self._httpx.aclose()

    @cached_property
    def response(self) -> T:
        assert self._response, "No response available"
        return self.response_cls.model_validate_response(self._response)

    @property
    @abstractmethod
    def response_cls(self) -> Type[T]:
        """Endpoint to use for the session."""

    def update_headers(self, headers: httpx.Headers) -> None:
        """Update headers for the request."""
        # Set headers
        headers.update(
            {
                "Accept": "application/json",
                "Origin": Endpoints.HOME,
                "Referer": f"{Endpoints.HOME}/",
            }
        )
        headers.update(self._settings.model_dump_headers())

    def update_cookies(self, cookies: httpx.Cookies) -> None:
        """Update cookies for the request."""
        cookies.update(self._cookies.model_dump())

    def update_session(self) -> None:
        """Save the session data."""
        if bool(self._response):
            self._cookies.model_update(self.response)
            self._settings.model_update(self.response)
