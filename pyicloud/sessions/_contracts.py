from __future__ import annotations

import sys
from abc import ABC, abstractmethod
from collections.abc import Callable
from copy import copy
from http.cookiejar import CookieJar
from types import get_original_bases
from typing import Any, ClassVar, Literal, Self, TypedDict, TypeVar, cast, get_args, get_origin

import httpx
from pydantic import BaseModel, Field, ValidationInfo, model_validator

from pyicloud.log import LOGGER
from pyicloud.models import LeafModel, _init_context_var
from pyicloud.models.bodies import BodyModel
from pyicloud.models.cookies import CookiesModel, MorselModel
from pyicloud.models.errors import Error, ServiceErrorsModel
from pyicloud.models.fields import ContentTypeType
from pyicloud.models.headers import HeadersModel


class Endpoint(LeafModel, ABC):
    verb: ClassVar[Literal["GET", "POST", "DELETE", "PUT"]] = "GET"
    content_type: ClassVar[ContentTypeType | None] = None

    @property
    def params(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, context={"by_meta": "params"})

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


class ResponseConfig(TypedDict, total=False):
    headers: type[HeadersModel]
    cookies: type[CookiesModel]
    body: type[BodyModel]


def _summarize_error_payload(response: httpx.Response, *, max_chars: int = 512) -> str:
    raw = response.content.decode("utf-8", errors="replace").strip()
    if not raw:
        return f"HTTP {response.status_code} error response."
    if len(raw) > max_chars:
        raw = f"{raw[:max_chars]}..."
    return f"HTTP {response.status_code} error response: {raw}"


def _parse_service_errors(response: httpx.Response) -> list[Error]:
    try:
        parsed = ServiceErrorsModel.model_validate_json(response.content)
    except Exception as exc:  # noqa: BLE001 - upstream payloads can be malformed
        LOGGER.warning("Could not parse service errors payload: %s", exc)
        return [Error(code=response.status_code, message=_summarize_error_payload(response))]

    if parsed.service_errors:
        return parsed.service_errors

    return [Error(code=response.status_code, message=_summarize_error_payload(response))]


class BaseResponse[H: HeadersModel, C: CookiesModel, B: BodyModel](BaseModel):
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
        return not self.is_error(self.status_code)

    @classmethod
    def is_error(cls, status_code: int) -> bool:
        return status_code >= 400

    @classmethod
    def create(cls, response: httpx.Response, *, data: Any = None) -> Self:
        data = data or {}
        data.setdefault("status_code", response.status_code)
        data.setdefault("headers", cls._config["headers"].model_validate({}, context={"headers": response.headers}))  # type: ignore[arg-type]
        data.setdefault("cookies", cls._config["cookies"].model_validate({}, context={"cookies": response.cookies}))  # type: ignore[arg-type]

        if response.content:
            content_type = cast(str, response.headers.get("content-type", "")).lower()
            is_json_response = content_type.startswith("application/json")
            if not is_json_response:
                LOGGER.warning("Response content is not JSON: %s", response.content)
            elif cls.is_error(response.status_code):
                data.setdefault("errors", _parse_service_errors(response))
            elif cls._config.get("body") is not None:
                data.setdefault("body", cls._config["body"].model_validate_json(response.content))  # type: ignore[arg-type]

        return cls(**data)

    @model_validator(mode="wrap")
    @classmethod
    def model_validate_from_response(cls, data: dict[str, Any], handler: Callable, info: ValidationInfo) -> Self:
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
        for key, value in return_data.items():
            if not isinstance(value, cls._config[key]):
                return_data[key] = cast(BaseModel, cls._config[key]).model_validate(
                    value or copy(data),
                    context=info.context,
                )
        return handler(return_data)

    _DEFAULT = object()

    def create_request(self, context: dict[str, Any] | object = _DEFAULT) -> httpx.Request:
        # This method is frequently accessed as a property helper, so
        # context is obtained from `_init_context_var` when not provided.
        if context == self._DEFAULT:
            context = _init_context_var.get()
        if not isinstance(context, dict):
            context = {}

        s_info = context.get("request", {})

        hs_info: dict[str, Any] = s_info.get("headers", {})
        hs_info.setdefault("context", {})
        hs_info["context"]["by_meta"] = "header"
        headers = self.headers.model_dump(**hs_info)

        cs_info = s_info.get("cookies", {})
        cs_info.setdefault("context", {})
        cs_info["context"]["by_meta"] = "cookie"
        jar, cookies = CookieJar(), dict(self.cookies.model_dump(by_alias=True, **cs_info))

        for morsel_data in cookies.values():
            if morsel_data is None:
                continue
            if not isinstance(morsel_data, dict):
                raise TypeError(f"Invalid morsel type: {type(morsel_data)}")

            host = httpx.URL(self.endpoint.url).host
            domain = morsel_data["domain"]
            exclude = None
            if domain and domain not in host:
                if morsel_data.get("name") in {"dslang", "site"}:
                    morsel_data = dict(morsel_data)
                    morsel_data["domain"] = host
                else:
                    exclude = "domain"
                    LOGGER.warning(
                        "Cookie '%s' domain mismatch. Expected: '%s', got: '%s'.",
                        morsel_data["name"],
                        host,
                        domain,
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


__all__ = [
    "BaseRequest",
    "BaseResponse",
    "DynamicEndpoint",
    "Endpoint",
    "RequestConfig",
    "ResponseConfig",
    "StaticEndpoint",
    "_resolve_model_type",
]
