from __future__ import annotations

from abc import ABC, abstractmethod
from copy import copy
from functools import cached_property
from http.cookiejar import CookieJar
from typing import Any, Callable, ClassVar, Generic, Literal, Self, Sequence, Type, TypedDict, TypeVar, cast, override

import httpx
from pydantic import BaseModel, Field, ValidationInfo, model_validator

from pyicloud.constants import AppleHeaders as Header
from pyicloud.constants import Endpoints
from pyicloud.log import PyiCloudPasswordFilter, logger_get
from pyicloud.models.body import BodyModel
from pyicloud.models.cookies import Cookies, CookiesModel
from pyicloud.models.errors import Error, ServiceErrorsModel
from pyicloud.models.headers import HeadersModel
from pyicloud.models.morsel import MorselModel
from pyicloud.models.settings import Settings
from pyicloud.models.types import _init_context_var


class Endpoint(BaseModel):
    # Constants
    url: ClassVar[str]
    verb: ClassVar[Literal["GET", "POST", "DELETE", "PUT"]] = "GET"
    content_type: ClassVar[str] = "application/json"


H = TypeVar("H", bound=HeadersModel)
C = TypeVar("C", bound=CookiesModel)
B = TypeVar("B", bound=BodyModel)
U = TypeVar("U", bound=Endpoint)
E = TypeVar("E", bound=Error)


class ResponseConfig(TypedDict, total=False):
    headers: type[HeadersModel]
    cookies: type[CookiesModel]
    body: type[BodyModel]


class BaseResponse(BaseModel, Generic[H, C, B]):
    """Response data."""

    _config: ClassVar[ResponseConfig] = ResponseConfig(
        headers=HeadersModel,
        cookies=CookiesModel,
        body=BodyModel,
    )

    status_code: int

    headers: H
    cookies: C

    body: B | None = None
    errors: list[Error] = Field(default=[])

    # Common Headers that must be stored as config
    @classmethod
    def __pydantic_init_subclass__(cls, **kwargs):
        # Update config with default values for bae class
        new_config = ResponseConfig(
            headers=HeadersModel,
            cookies=CookiesModel,
            body=BodyModel,
        )
        new_config.update(cls._config)
        cls._config = new_config

    def __bool__(self):
        """Return True if the response is successful."""
        return not self.is_error(self.status_code)

    @classmethod
    def is_error(cls, status_code: int) -> bool:
        """Return True if the response is an error."""
        return status_code >= 400

    @classmethod
    def model_validate_response(cls, response: httpx.Response, *, data: Any = None) -> Self:
        """Create a response from a httpx response."""
        data = data or {}
        # Parse status code
        data.setdefault("status_code", response.status_code)
        # Parse Headers
        data.setdefault("headers", cls._config["headers"].model_validate({}, context={"headers": response.headers}))  # type: ignore
        # Parse Cookies
        data.setdefault("cookies", cls._config["cookies"].model_validate({}, context={"cookies": response.cookies}))  # type: ignore
        # Parse Body
        if response.headers["content-type"].startswith("application/json"):
            if cls.is_error(response.status_code):
                error = ServiceErrorsModel.model_validate_json(response.content)
                data.setdefault("errors", error.service_errors)
            elif cls._config.get("body") is not None:
                data.setdefault("body", cls._config["body"].model_validate_json(response.content))  # type: ignore
        # create a new instance of the response
        return cls(**data)

    @model_validator(mode="wrap")
    @classmethod
    def model_validate_from_response(cls, data: dict[str, Any], handler: Callable, info: ValidationInfo) -> Self:
        """Create a response from a httpx response."""
        response: httpx.Response | None = None

        if isinstance(info.context, dict):
            response = info.context.get("response", None)

            if isinstance(response, httpx.Response):
                return cls.model_validate_response(response, data=data)

        return handler(data)


class RequestConfig(TypedDict, total=False):
    endpoint: type[Endpoint]
    headers: type[HeadersModel]
    cookies: type[CookiesModel]
    body: type[BodyModel]


class BaseRequest(BaseModel, Generic[H, C, B, U]):
    _config: ClassVar[RequestConfig] = RequestConfig(
        endpoint=Endpoint,
        headers=HeadersModel,
        cookies=CookiesModel,
        body=BodyModel,
    )

    endpoint: U
    headers: H
    cookies: C
    body: B

    # Common Headers that must be stored as config
    @classmethod
    def __pydantic_init_subclass__(cls, **kwargs):
        # Update config with default values for bae class
        new_config = RequestConfig(
            headers=HeadersModel,
            cookies=CookiesModel,
            body=BodyModel,
            endpoint=Endpoint,
        )
        new_config.update(cls._config)
        cls._config = new_config
        cls.model_rebuild(force=True)

    @model_validator(mode="wrap")
    @classmethod
    def model_validate_request(cls, data: dict[str, Any], handler: Callable, info: ValidationInfo) -> Self:
        return_data = {k: data.pop(k, None) for k in cls.model_fields.keys()}
        for k, v in return_data.items():
            # If key contents is None, or a dict, (Not a BaseModel, use it to create a new model)
            if not isinstance(v, cls._config[k]):
                # If not 'endpoint' or 'body' attributes, assume all dict may #
                # contain valid data for thoss models and let them validate it
                return_data[k] = cast(BaseModel, cls._config[k]).model_validate(v or copy(data), context=info.context)
        # Create a new instance of the request
        return handler(return_data)

    _DEFAULT = object()

    def model_dump_httpx_request(self, context: dict[str, Any] | object = _DEFAULT) -> httpx.Request:
        """Dump the request data."""
        # Ensure we have a valid context. Tbis method will be called from a property, so
        # threre's no way to pass context directly to it, so we use the _init_context_var
        # to store it. hack
        if context == self._DEFAULT:
            context = _init_context_var.get()
        if not isinstance(context, dict):
            context = {}

        s_info = context.get("request", {})

        # Set headers serialization info
        hs_info: dict[str, Any] = s_info.get("headers", {})
        hs_info.setdefault("context", {})
        hs_info["context"]["by_meta"] = "header"
        headers = self.headers.model_dump(**hs_info)

        # Set cookies serialization info
        cs_info = s_info.get("cookies", {})
        cs_info.setdefault("context", {})
        cs_info["context"]["by_meta"] = "cookie"
        jar, cookies = CookieJar(), dict(self.cookies.model_dump(by_alias=True, **cs_info))
        list(map(lambda x: jar.set_cookie(MorselModel.as_cookie(x)), cookies.values()))

        return httpx.Request(
            method=self.endpoint.verb,
            url=self.endpoint.url,
            headers=headers,
            cookies=jar,
            json=self.body.json_data,
            content=self.body.content,
        )


T = TypeVar("T", bound="BaseRequest")
K = TypeVar("K", bound="BaseResponse")


class BaseTransport(Generic[T, K], ABC):
    ENDPOINT: str

    _cookies: Cookies
    _settings: Settings

    # Transport client
    _client: httpx.AsyncClient
    _request: httpx.Request | None
    _response: httpx.Response | None
    _data: dict[str, Any]

    def __init__(
        self,
        settings: Settings,
        cookies: Cookies,
        *,
        client: httpx.AsyncClient | None = None,
        data: dict[str, Any] | None = None,
        # context: dict[str, Any] | None = None,
    ):
        client = client or httpx.AsyncClient(follow_redirects=True)

        self._cookies = cookies
        self._settings = settings

        self._client = client
        self._request = None
        self._response = None
        self._data = data or {}

        # Add a hook to response events, so last one is automatically
        # stored in self._response
        async def request_hook(value: httpx.Request) -> None:
            self._request = value

        async def response_hook(value: httpx.Response) -> None:
            self._response = value
            await value.aread()

        self._client.event_hooks["request"].append(request_hook)
        self._client.event_hooks["response"].append(response_hook)

        # set password filter
        PyiCloudPasswordFilter.register(self, logger=logger_get("http"))

    async def __aenter__(self):
        return self._client

    async def __aexit__(self, exc_type, exc, tb):
        await self._client.aclose()

    @cached_property
    def response(self) -> K:
        assert self._response, "No response available"
        response = self.response_cls.model_validate(
            {},
            context={
                "response": self._response,
                "settings": self._settings,
                "cookies": self._cookies,
            },
        )
        return response

    @cached_property
    def request(self) -> T:
        assert not self._request, "Request already set"
        request = self.request_cls.model_validate(
            self._data,
            context={
                "settings": self._settings,
                "cookies": self._cookies,
            },
        )
        return request

    @property
    @abstractmethod
    def request_cls(self) -> Type[T]:
        """Endpoint to use for the session."""

    @property
    @abstractmethod
    def response_cls(self) -> Type[K]:
        """Endpoint to use for the session."""

    def dump_headers(
        self,
        headers: httpx.Headers | None = None,
        *,
        include: Sequence[str] | None = None,
        exclude: Sequence[str] | None = None,
        exclude_unset=True,
        exclude_defaults=False,
        context: Any = None,
    ) -> httpx.Headers:
        """Update headers for the request."""
        # Set headers
        headers = headers if headers is not None else httpx.Headers()

        headers.update(
            {
                "Accept": "application/json",
                "Origin": Endpoints.HOME,
                "Referer": f"{Endpoints.HOME}/",
            }
        )
        headers.update(
            self._settings.model_dump_by_meta(
                by_meta="header",
                include=include,
                exclude=exclude,
                exclude_unset=exclude_unset,
                exclude_defaults=exclude_defaults,
            )
        )
        return headers

    def dump_cookies(
        self,
        cookies: httpx.Cookies | None = None,
        *,
        include: Sequence[str] | None = None,
        exclude: Sequence[str] | None = None,
        exclude_unset=True,
        exclude_defaults=False,
        context: Any = None,
    ) -> httpx.Cookies:
        """Update cookies for the request."""
        cookies = cookies if cookies is not None else httpx.Cookies()
        cookies.update(
            self._cookies.model_dump(
                by_alias=True,
                include=include,
                exclude=exclude,
                exclude_unset=exclude_unset,
                exclude_defaults=exclude_defaults,
            )
        )
        return cookies

    def dump_content(
        self,
        content: bytes | dict[str, Any] | None = None,
        *,
        include: Sequence[str] | None = None,
        exclude: Sequence[str] | None = None,
        exclude_unset=True,
        exclude_defaults=False,
        context: Any = None,
    ) -> bytes | dict[str, Any] | None:
        """Update the content for the request."""
        if isinstance(content, dict):
            content.update(
                **self._settings.model_dump_by_meta(
                    by_meta="body",
                    include=include,
                    exclude=exclude,
                    exclude_unset=exclude_unset,
                    exclude_defaults=exclude_defaults,
                )
            )
        # If content is not a dict, bypass it
        return content

    def update_session(
        self,
        *,
        include: Sequence[str] | None = None,
        exclude: Sequence[str] | None = None,
    ) -> None:
        """Save the session data."""
        if self._response is not None:
            self._cookies.model_validate_from_response(self.response)
            self._settings.model_validate_from_response(self.response)


class OAuthTransport(BaseTransport[T, K], ABC):
    @override
    def dump_headers(
        self,
        headers: httpx.Headers | None = None,
        *,
        include: Sequence[str] | None = None,
        exclude: Sequence[str] | None = None,
        exclude_unset=True,
        exclude_defaults=False,
        context: Any = None,
    ):
        # Don't set country code header for outbound request
        headers = super().dump_headers(
            headers,
            include=include,
            exclude=exclude or [Header.COUNTRY_CODE],
            exclude_unset=exclude_unset,
            exclude_defaults=exclude_defaults,
            context=context,
        )

        new_headers = {
            "content-type": "application/json",
            Header.OAUTH_CLIENT_ID: "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d",
            Header.OAUTH_CLIENT_TYPE: "firstPartyAuth",
            Header.OAUTH_REDIRECT_URI: Endpoints.HOME,
            Header.OAUTH_REQUIRE_GRANT_CODE: "true",
            Header.OAUTH_RESPONSE_TYPE: "code",
            Header.OAUTH_RESPONSE_MODE: "web_message",
            Header.OAUTH_STATE: self._settings["client_settings.client_id"],
            Header.WIDGET_KEY: "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d",
        }

        for key, value in new_headers.items():
            headers.setdefault(key.lower(), value)

        return headers

    async def __aexit__(self, exc_type, exc, tb):
        self.update_session()
        await super().__aexit__(exc_type, exc, tb)
