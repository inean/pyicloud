from __future__ import annotations

import sys
from abc import ABC, abstractmethod
from collections.abc import Callable, Sequence
from copy import copy
from dataclasses import asdict, dataclass, field, fields
from functools import WRAPPER_ASSIGNMENTS, cached_property
from http.cookiejar import CookieJar
from time import perf_counter
from types import UnionType, get_original_bases
from typing import (
    Any,
    ClassVar,
    Literal,
    ParamSpec,
    Self,
    TypedDict,
    TypeVar,
    cast,
    get_args,
    get_origin,
    overload,
    override,
)

import httpx
from pydantic import BaseModel, Field, ValidationInfo, model_validator

from pyicloud.adapters.upstream_probe import get_upstream_probe, upstream_capture_body_max_bytes
from pyicloud.constants import AppleHeaders as Header
from pyicloud.constants import Endpoints
from pyicloud.log import LOGGER, PyiCloudPasswordFilter, logger_get
from pyicloud.models import LeafModel, _init_context_var
from pyicloud.models.bodies import BodyModel
from pyicloud.models.cookies import Cookies, CookiesModel, MorselModel
from pyicloud.models.errors import Error, ServiceErrorsModel
from pyicloud.models.fields import ContentTypeType
from pyicloud.models.headers import HeadersModel
from pyicloud.models.settings import Settings
from pyicloud.paths import CookiesJar, SettingsFile
from pyicloud.upstream import build_request_event, build_response_event


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


class BaseResponse[H: HeadersModel, C: CookiesModel, B: BodyModel](BaseModel):
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
    errors: list[Error] = Field(default_factory=list)

    @classmethod
    def __pydantic_init_subclass__(cls, **kwargs):
        super().__pydantic_init_subclass__(**kwargs)

        config_data = _resolve_config_from_origin(
            cls=cls,
            expected_origin=BaseResponse,
            fields=("headers", "cookies", "body"),
            defaults={"headers": HeadersModel, "cookies": CookiesModel, "body": BodyModel},
        )

        explicit_config = cls.__dict__.get("_config")
        if isinstance(explicit_config, dict):
            config_data.update(explicit_config)

        cls._config = ResponseConfig(**config_data)  # type: ignore[assignment]
        cls.model_rebuild(force=True)

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


def _resolve_model_type(annotation: Any, *, module_name: str) -> type[Any] | None:
    if isinstance(annotation, str):
        module = sys.modules.get(module_name)
        if module and hasattr(module, annotation):
            annotation = getattr(module, annotation)
    return annotation if isinstance(annotation, type) else None


def _resolve_parametric_base_from_original_bases(
    cls: type[Any], *, expected_origin: type[Any]
) -> tuple[type[Any], tuple[Any, ...]] | None:
    for base in get_original_bases(cls):
        origin = get_origin(base)
        if not isinstance(origin, type) or not issubclass(origin, expected_origin):
            if not isinstance(base, type):
                continue
            metadata = getattr(base, "__pydantic_generic_metadata__", None)
            if not isinstance(metadata, dict):
                continue
            origin = metadata.get("origin")
            args = metadata.get("args", ())
            if not isinstance(origin, type) or not issubclass(origin, expected_origin):
                continue
            if not isinstance(args, tuple):
                continue
            return origin, args
        args = get_args(base)
        if not isinstance(args, tuple):
            continue
        return origin, args
    return None


def _resolve_config_from_origin(
    *,
    cls: type[Any],
    expected_origin: type[Any],
    fields: tuple[str, ...],
    defaults: dict[str, type[Any]],
) -> dict[str, type[Any]]:
    config_data: dict[str, type[Any]] = dict(defaults)
    metadata = _resolve_parametric_base_from_original_bases(cls, expected_origin=expected_origin)
    if metadata is None:
        return config_data

    origin, args = metadata
    config_data.update(getattr(origin, "_config", {}))

    if len(args) == len(fields):
        for i, fname in enumerate(fields):
            ann = args[i]
            if ann is None or isinstance(ann, TypeVar):
                continue
            ann_type = _resolve_model_type(ann, module_name=cls.__module__)
            if ann_type is not None:
                config_data[fname] = ann_type

    origin_metadata = getattr(origin, "__pydantic_generic_metadata__", {})
    parameters = origin_metadata.get("parameters", ())
    if isinstance(parameters, tuple) and len(parameters) == len(args):
        type_map = dict(zip(parameters, args))
        for key, value in tuple(config_data.items()):
            mapped = type_map.get(value)
            mapped_type = _resolve_model_type(mapped, module_name=cls.__module__)
            if mapped_type is not None:
                config_data[key] = mapped_type

    return config_data


class BaseRequest[H: HeadersModel, C: CookiesModel, B: BodyModel, U: Endpoint](BaseModel):
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
        super().__pydantic_init_subclass__(**kwargs)

        config_data = _resolve_config_from_origin(
            cls=cls,
            expected_origin=BaseRequest,
            fields=("headers", "cookies", "body", "endpoint"),
            defaults={"endpoint": Endpoint, "headers": HeadersModel, "cookies": CookiesModel, "body": BodyModel},
        )

        explicit_config = cls.__dict__.get("_config")
        if isinstance(explicit_config, dict):
            config_data.update(explicit_config)

        cls._config = RequestConfig(**config_data)  # type: ignore[assignment]
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


class BaseTransport[T: BaseRequest, K: BaseResponse](ABC):
    _cookies: Cookies
    _settings: Settings

    # Transport client
    _client: httpx.AsyncClient
    _request: httpx.Request | None
    _response: httpx.Response | None
    _data: dict[str, Any]
    _probe_started_at: dict[int, float]
    _probe_request_events: dict[int, Any]

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
        self._probe_started_at = {}
        self._probe_request_events = {}

        # Add a hook to response events, so last one is automatically
        # stored in self._response
        async def request_hook(value: httpx.Request) -> None:
            self._request = value
            probe = get_upstream_probe()
            body_max_bytes = upstream_capture_body_max_bytes()
            request_event = build_request_event(
                request=value,
                body_max_bytes=body_max_bytes,
                attempt=1,
            )
            self._probe_request_events[id(value)] = request_event
            self._probe_started_at[id(value)] = perf_counter()
            probe.on_request(request_event)

        async def response_hook(value: httpx.Response) -> None:
            self._response = value
            await value.aread()
            probe = get_upstream_probe()
            body_max_bytes = upstream_capture_body_max_bytes()
            request_id = id(value.request)
            request_event = self._probe_request_events.pop(request_id, None)
            started = self._probe_started_at.pop(request_id, None)
            if request_event is None:
                request_event = build_request_event(
                    request=value.request,
                    body_max_bytes=body_max_bytes,
                    attempt=1,
                )
                probe.on_request(request_event)
            duration_ms = ((perf_counter() - started) * 1000.0) if started is not None else 0.0
            probe.on_response(
                build_response_event(
                    request_event=request_event,
                    response=value,
                    duration_ms=duration_ms,
                    body_max_bytes=body_max_bytes,
                )
            )

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
        response_cls = self._resolve_response_model()
        response = response_cls.model_validate(
            {},
            context={
                "response": self._response,
                "settings": self._settings,
                "cookies": self._cookies,
            },
        )
        return cast(K, response)

    @cached_property
    def request(self) -> T:
        assert not self._request, "Request already set"
        candidates = self._resolve_request_candidates()
        context = self._request_context()

        if len(candidates) == 1:
            request = candidates[0].model_validate(copy(self._data), context=context)
            return cast(T, request)

        failures: list[tuple[str, Exception]] = []
        for request_cls in candidates:
            try:
                request = request_cls.model_validate(copy(self._data), context=context)
            except Exception as exc:  # noqa: BLE001 - we need candidate-by-candidate probing
                failures.append((request_cls.__name__, exc))
                continue
            return cast(T, request)

        details = "; ".join(f"{name}: {exc!r}" for name, exc in failures)
        raise TypeError(f"Could not resolve request model for {type(self).__name__}: {details}")

    def _request_context(self) -> dict[str, Any]:
        return {
            "settings": self._settings,
            "cookies": self._cookies,
        }

    @classmethod
    def _resolve_transport_generic_args(cls) -> tuple[Any, Any]:
        for mro_cls in cls.__mro__:
            for base in get_original_bases(mro_cls):
                origin = get_origin(base)
                if not isinstance(origin, type) or not issubclass(origin, BaseTransport):
                    continue
                args = get_args(base)
                if len(args) != 2:
                    continue
                return args[0], args[1]
        raise TypeError(f"Could not resolve transport generic arguments for {cls.__name__}")

    @classmethod
    def _resolve_request_candidates(cls) -> list[type[BaseRequest]]:
        request_ann, _ = cls._resolve_transport_generic_args()
        origin = get_origin(request_ann)

        if origin in (UnionType,):
            candidates = [
                item for item in get_args(request_ann) if isinstance(item, type) and issubclass(item, BaseRequest)
            ]
            if candidates:
                return candidates
            raise TypeError(f"Union request annotation has no BaseRequest candidates: {request_ann!r}")

        request_cls = _resolve_model_type(request_ann, module_name=cls.__module__)
        if request_cls is None or not issubclass(request_cls, BaseRequest):
            raise TypeError(f"Invalid request annotation for {cls.__name__}: {request_ann!r}")
        return [request_cls]

    @classmethod
    def _resolve_response_model(cls) -> type[BaseResponse]:
        _, response_ann = cls._resolve_transport_generic_args()
        response_cls = _resolve_model_type(response_ann, module_name=cls.__module__)
        if response_cls is None or not issubclass(response_cls, BaseResponse):
            raise TypeError(f"Invalid response annotation for {cls.__name__}: {response_ann!r}")
        return response_cls

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
            elif value is not None and not isinstance(value, str | bytes):
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


class OAuthTransport[T: BaseRequest, K: BaseResponse](BaseTransport[T, K], ABC):
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


type IncEx = set[int] | set[str] | dict[int, Any] | dict[str, Any] | None


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


def _default_serialize_settings() -> Serialize:
    return Serialize(
        options=SerializationInfo(
            by_alias=True,
            exclude_none=True,
            indent=2,
        ),
    )


def _default_serialize_cookies() -> Serialize:
    return Serialize(
        options=SerializationInfo(
            by_alias=True,
            exclude_defaults=True,
            exclude_none=True,
            exclude_unset=True,
            indent=2,
        ),
    )


def _copy_serialization_info(value: SerializationInfo | dict[str, Any] | None = None) -> SerializationInfo:
    if value is None:
        return SerializationInfo()
    if isinstance(value, SerializationInfo):
        return SerializationInfo(**value.to_dict())
    if isinstance(value, dict):
        return SerializationInfo(**value)
    raise TypeError("Serialization options must be a SerializationInfo, dict, or None")


def _copy_serialize(value: Serialize | dict[str, Any] | None = None) -> Serialize:
    if value is None:
        return Serialize()
    if isinstance(value, Serialize):
        return Serialize(
            read=value.read,
            write=value.write,
            options=_copy_serialization_info(value.options),
        )
    if isinstance(value, dict):
        payload = dict(value)
        payload["options"] = _copy_serialization_info(payload.get("options"))
        return Serialize(**payload)
    raise TypeError("Serialize config must be a Serialize instance, dict, or None")


def _merge_serialization_info(
    *,
    base: SerializationInfo,
    override: SerializationInfo | dict[str, Any] | None,
) -> SerializationInfo:
    merged = _copy_serialization_info(base)
    if override is None:
        return merged
    if isinstance(override, SerializationInfo):
        merged.update(_copy_serialization_info(override))
        return merged
    if isinstance(override, dict):
        for config_field in fields(SerializationInfo):
            if config_field.name in override:
                setattr(merged, config_field.name, override[config_field.name])
        return merged
    raise TypeError("Serialization options must be a SerializationInfo, dict, or None")


def _normalize_serialize_config(
    value: Serialize | dict[str, Any] | None,
    *,
    default: Serialize,
) -> Serialize:
    merged = _copy_serialize(default)
    if value is None:
        return merged
    if isinstance(value, Serialize):
        merged.update(_copy_serialize(value))
        return merged
    if isinstance(value, dict):
        if "read" in value:
            merged.read = value["read"]
        if "write" in value:
            merged.write = value["write"]
        if "options" in value:
            merged.options = _merge_serialization_info(
                base=merged.options,
                override=value.get("options"),
            )
        return merged
    raise TypeError("Serialize config must be a Serialize instance, dict, or None")


@overload
def serialize[BT: BaseTransport](cls: type[BT]) -> type[BT]: ...


@overload
def serialize[BT: BaseTransport](
    cls: type[BT],
    *,
    settings: Serialize | dict[str, Any] | None = None,
    cookies: Serialize | dict[str, Any] | None = None,
) -> type[BT]: ...


def serialize[BT: BaseTransport](
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

            self._serialize_settings_ = _normalize_serialize_config(
                settings,
                default=_default_serialize_settings(),
            )
            self._serialize_cookies_ = _normalize_serialize_config(
                cookies,
                default=_default_serialize_cookies(),
            )

            context_data = _init_context_var.get()
            runtime_serialize_info = context_data.get("serialize_info", {}) if isinstance(context_data, dict) else {}
            if isinstance(runtime_serialize_info, dict):
                self._serialize_settings_ = _normalize_serialize_config(
                    runtime_serialize_info.get("settings"),
                    default=self._serialize_settings_,
                )
                self._serialize_cookies_ = _normalize_serialize_config(
                    runtime_serialize_info.get("cookies"),
                    default=self._serialize_cookies_,
                )

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
