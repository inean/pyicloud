from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Sequence
from copy import copy
from dataclasses import asdict, dataclass, field, fields
from functools import WRAPPER_ASSIGNMENTS, cached_property
from http.cookiejar import CookieJar
from typing import (
    Any,
    ClassVar,
    Generic,
    Literal,
    ParamSpec,
    Self,
    Type,
    TypeAlias,
    TypedDict,
    TypeVar,
    cast,
    get_args,
    overload,
    override,
)

import httpx
from pydantic import BaseModel, Field, ValidationInfo, model_validator

from pyicloud.constants import AppleHeaders as Header
from pyicloud.constants import Endpoints
from pyicloud.log import LOGGER, PyiCloudPasswordFilter, logger_get
from pyicloud.models import LeafModel, MetaFields, _init_context_var
from pyicloud.models.bodies import BodyModel
from pyicloud.models.cookies import Cookies, CookiesModel, MorselModel
from pyicloud.models.errors import Error, ServiceErrorsModel
from pyicloud.models.fields import ContentTypeType
from pyicloud.models.headers import HeadersModel
from pyicloud.models.settings import Settings
from pyicloud.paths import CookiesJar, SettingsFile


class Endpoint(LeafModel, ABC):
    # Constants
    verb: ClassVar[Literal["GET", "POST", "DELETE", "PUT"]] = "GET"
    content_type: ClassVar[ContentTypeType | None] = None

    @property
    def params(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, context=dict(by_meta="params"))

    @property
    @abstractmethod
    def url(self) -> httpx.URL: ...


class DynamicEndpoint(Endpoint):
    path: ClassVar[str]
    root: str

    @property
    def url(self) -> httpx.URL:
        path = self.path if self.path.startswith("/") else f"/{self.path}"
        root = self.root if self.root.endswith("/") else f"{self.root}/"
        return httpx.URL(f"{root[:-1]}{path}")


class StaticEndpoint(Endpoint):
    endpoint: ClassVar[str]

    @property
    def url(self) -> httpx.URL:
        return httpx.URL(self.endpoint)


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
    def create(cls, response: httpx.Response, *, data: Any = None) -> Self:
        """Create a response from a httpx response."""
        data = data or {}
        # Parse status code
        data.setdefault("status_code", response.status_code)
        # Parse Headers
        data.setdefault("headers", cls._config["headers"].model_validate({}, context={"headers": response.headers}))  # type: ignore
        # Parse Cookies
        data.setdefault("cookies", cls._config["cookies"].model_validate({}, context={"cookies": response.cookies}))  # type: ignore
        # Parse Body
        if len(response.content) > 0:
            if not cast(str, response.headers.get("content-type", "")).lower().startswith("application/json"):
                LOGGER.warning("Response content is not JSON: %s", response.content)
            elif cls.is_error(response.status_code):
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
                return cls.create(response, data=data)

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

    def create_request(self, context: dict[str, Any] | object = _DEFAULT) -> httpx.Request:
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

        for morsel_data in cookies.values():
            if morsel_data is None:
                continue
            assert isinstance(morsel_data, dict), f"Invalid morsel type: {type(morsel_data)}"
            host = httpx.URL(self.endpoint.url).host
            domain = morsel_data["domain"]
            exclude = None
            if domain and domain not in host:
                # Apple may return locale cookies bound to .apple.com while setup
                # endpoints live under setup.icloud.com. Rebind these per-request.
                if morsel_data.get("name") in {"dslang", "site"}:
                    morsel_data = dict(morsel_data)
                    morsel_data["domain"] = host
                else:
                    exclude = "domain"
                    LOGGER.warning(
                        f"Cookie '{morsel_data['name']}' domain mismatch. Expected: '{host}', got: '{domain}'."
                    )
            jar.set_cookie(MorselModel.as_cookie(morsel_data, exclude=exclude))

        return httpx.Request(
            method=self.endpoint.verb,
            url=self.endpoint.url,
            params=self.endpoint.params,
            headers=headers,
            cookies=jar,
            json=self.body.json_data,
            content=self.body.content,
        )


T = TypeVar("T", bound="BaseRequest")
K = TypeVar("K", bound="BaseResponse")


class BaseTransport(Generic[T, K], ABC):
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
    def request_cls(self) -> type[T]:
        """Endpoint to use for the session."""

    @property
    @abstractmethod
    def response_cls(self) -> type[K]:
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
        dynamic_headers = self._settings.model_dump_by_meta(
            by_meta="header",
            include=include,
            exclude=exclude,
            exclude_unset=exclude_unset,
            exclude_defaults=exclude_defaults,
        )
        # httpx requires header values as str/bytes.
        for key, value in dynamic_headers.items():
            if isinstance(value, bool):
                dynamic_headers[key] = "true" if value else "false"
            elif value is not None and not isinstance(value, (str, bytes)):
                dynamic_headers[key] = str(value)
        headers.update(dynamic_headers)
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

    async def send_request(self, client: httpx.AsyncClient | None = None) -> httpx.Response:
        """Send the transport request using the provided client or the transport client."""
        client = client or self._client
        return await client.send(self.request.create_request())


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

    @override
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
        body = self.request.body
        if (json_data := body.json_data) is not None:
            content = content or {}
            assert isinstance(content, dict), "Content must be a dictionary."
            content.update(json_data)
            return content
        # Case where body is not a dict
        return body.content

    async def __aexit__(self, exc_type, exc, tb):
        self.update_session()
        await super().__aexit__(exc_type, exc, tb)


BT = TypeVar("BT", bound=BaseTransport)
P = ParamSpec("P")


IncEx: TypeAlias = set[int] | set[str] | dict[int, Any] | dict[str, Any] | None


@dataclass
class BaseSerialize:
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def __bool__(self) -> bool:
        return any(getattr(self, f.name) != f.default for f in fields(self))

    def update(self, other: Self) -> Self:
        # other will return False if set with default values.
        # If any member is set, it will return True
        if bool(other):
            for f in fields(self):
                if (value := getattr(self, f.name)) and hasattr(value, "update"):
                    value.update(getattr(other, f.name))
                elif (value := getattr(other, f.name)) != f.default:
                    setattr(self, f.name, value)
        return self


@dataclass
class SerializationInfo(BaseSerialize):
    indent: int | None = None
    include: IncEx = None
    exclude: IncEx = None
    context: dict[str, Any] | None = None
    by_alias: bool = False
    exclude_unset: bool = False
    exclude_defaults: bool = False
    exclude_none: bool = False
    round_trip: bool = False
    warnings: bool | Literal["none", "warn", "error"] = True
    serialize_as_any: bool = False


@dataclass
class Serialize(BaseSerialize):
    read: bool = False
    write: bool = True
    options: SerializationInfo = field(default_factory=SerializationInfo)


@overload
def serialize(cls: type[BT]) -> type[BT]: ...


@overload
def serialize(
    cls: type[BT],
    *,
    settings: Serialize | dict[str, Any] | None = None,
    cookies: Serialize | dict[str, Any] | None = None,
) -> type[BT]: ...


def serialize(
    cls: type[BT] | None = None,
    *,
    settings: Serialize | dict[str, Any] | None = None,
    cookies: Serialize | dict[str, Any] | None = None,
) -> type[BT] | Callable[[type[BT]], type[BT]]:
    """Load and store session and cookies when entering and exiting the context manager."""

    # If no class is provided, return a decorator that will call configure with the provided class
    if cls is None:

        def decorator(cls: type[BT]) -> type[BT]:
            return serialize(
                cls,
                settings=settings,
                cookies=cookies,
            )

        return decorator

    # Check if cls is a class
    if not isinstance(cls, type):
        raise TypeError("cls must be a class")

    class Wrapper(cls):
        """New wrapper that will extend the wrapper `cls` to make it look like `wrapped`"""

        def __init__(self, *args, **kwargs):
            assert issubclass(cls, cast(Any, BT.__bound__))

            context = _init_context_var.get()

            # Sanity Defaults
            self._serialize_settings_ = Serialize(
                options=SerializationInfo(
                    by_alias=True,
                    exclude_none=True,
                    indent=2,
                ),
            )
            # Settings set at decorator level
            if settings is not None:
                if isinstance(settings, dict):
                    self._serialize_settings_.update(Serialize(**settings))
                elif isinstance(settings, Serialize):
                    self._serialize_settings = settings

            # Sanity Defaults
            self._serialize_cookies_ = Serialize(
                options=SerializationInfo(
                    by_alias=True,
                    exclude_defaults=True,
                    exclude_none=True,
                    exclude_unset=True,
                    indent=2,
                ),
            )
            # cookies set at decorator level
            if cookies is not None:
                if isinstance(cookies, dict):
                    self._serialize_cookies_.update(Serialize(**cookies))
                elif isinstance(cookies, Serialize):
                    self._serialize_cookies = cookies

            # Info set at runtime
            if context := context.get("serialize_info", {}):
                assert isinstance(context, dict)

                if "settings" in context:
                    context_settings: dict[str, Any] | Serialize = context["settings"]
                    if isinstance(context_settings, dict):
                        self._serialize_settings_.update(Serialize(**context_settings))
                    elif isinstance(context_settings, Serialize):
                        self._serialize_settings_ = context_settings

                # cookies set at runtime
                if "cookies" in context:
                    context_cookies: dict[str, Any] | Serialize = context["cookies"]
                    if isinstance(context_cookies, dict):
                        self._serialize_cookies_.update(Serialize(**context_cookies))
                    elif isinstance(context_cookies, Serialize):
                        self._serialize_cookies_ = context_cookies

            # Call the original __init__ method
            super().__init__(*args, **kwargs)

        async def __aenter__(self: BT):
            # Load session and cookies
            wrapper = cast(Wrapper, self)
            if wrapper._serialize_settings_.read:
                SettingsFile(self._settings).loads()
            if wrapper._serialize_cookies_.read:
                if username := self._settings.account.username:
                    CookiesJar(self._cookies).loads(username=username)
            return await super().__aenter__()

        async def __aexit__(self, exc_type, exc, tb):
            # Call the original __aexit__ method
            result = await super().__aexit__(exc_type, exc, tb)
            # Write session and cookies
            wrapper = cast(Wrapper, self)
            if wrapper._serialize_settings_.write:
                SettingsFile(self._settings).saves(
                    **wrapper._serialize_settings_.options.to_dict(),
                )
            if wrapper._serialize_cookies_.write:
                username = self._settings.account.username
                assert username
                CookiesJar(self._cookies).saves(
                    username=username,
                    **wrapper._serialize_cookies_.options.to_dict(),
                )
            return result

    # Assign the attributes
    for attr in WRAPPER_ASSIGNMENTS:
        setattr(Wrapper, attr, getattr(cls, attr))

    return Wrapper  # type: ignore
