from __future__ import annotations

from abc import ABC
from collections.abc import Awaitable, Callable, Sequence
from copy import copy
from functools import cached_property
from time import perf_counter
from types import UnionType, get_original_bases
from typing import Any, cast, get_args, get_origin, override

import httpx

from pyicloud.constants import AppleHeaders as Header
from pyicloud.constants import Endpoints
from pyicloud.log import PyiCloudPasswordFilter, logger_get
from pyicloud.models.cookies import Cookies
from pyicloud.models.settings import Settings
from pyicloud.platform.telemetry.upstream import build_request_event, build_response_event

from ._contracts import BaseRequest, BaseResponse, _resolve_model_type

RequestHook = Callable[[httpx.Request], Awaitable[None]]
ResponseHook = Callable[[httpx.Response], Awaitable[None]]


def _probe_runtime() -> tuple[Any, int]:
    import pyicloud.sessions as sessions_module

    return sessions_module.get_upstream_probe(), sessions_module.upstream_capture_body_max_bytes()


class BaseTransport[T: BaseRequest, K: BaseResponse](ABC):
    _cookies: Cookies
    _settings: Settings

    _client: httpx.AsyncClient
    _owns_client: bool
    _request_hook: RequestHook
    _response_hook: ResponseHook

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
    ):
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(follow_redirects=True)

        self._cookies = cookies
        self._settings = settings

        self._request = None
        self._response = None
        self._data = data or {}
        self._probe_started_at = {}
        self._probe_request_events = {}

        self._request_hook = self._build_request_hook()
        self._response_hook = self._build_response_hook()
        self._attach_event_hooks()

        PyiCloudPasswordFilter.register(self, logger=logger_get("http"))

    def _build_request_hook(self) -> RequestHook:
        async def request_hook(value: httpx.Request) -> None:
            self._request = value
            probe, body_max_bytes = _probe_runtime()
            request_event = build_request_event(
                request=value,
                body_max_bytes=body_max_bytes,
                attempt=1,
            )
            self._probe_request_events[id(value)] = request_event
            self._probe_started_at[id(value)] = perf_counter()
            probe.on_request(request_event)

        return request_hook

    def _build_response_hook(self) -> ResponseHook:
        async def response_hook(value: httpx.Response) -> None:
            self._response = value
            await value.aread()

            probe, body_max_bytes = _probe_runtime()
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

        return response_hook

    def _attach_event_hooks(self) -> None:
        self._client.event_hooks.setdefault("request", []).append(self._request_hook)
        self._client.event_hooks.setdefault("response", []).append(self._response_hook)

    def _detach_event_hooks(self) -> None:
        request_hooks = self._client.event_hooks.get("request", [])
        response_hooks = self._client.event_hooks.get("response", [])

        if self._request_hook in request_hooks:
            request_hooks.remove(self._request_hook)
        if self._response_hook in response_hooks:
            response_hooks.remove(self._response_hook)

    async def __aenter__(self):
        return self._client

    async def __aexit__(self, exc_type, exc, tb):
        self._detach_event_hooks()
        if self._owns_client:
            await self._client.aclose()

    @cached_property
    def response(self) -> K:
        if self._response is None:
            raise RuntimeError("No response available. Call send_request() before accessing response.")

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
        if self._request is not None:
            raise RuntimeError("Request already resolved from a sent HTTP transaction.")

        candidates = self._resolve_request_candidates()
        context = self._request_context()

        if len(candidates) == 1:
            request = candidates[0].model_validate(copy(self._data), context=context)
            return cast(T, request)

        failures: list[tuple[str, Exception]] = []
        for request_cls in candidates:
            try:
                request = request_cls.model_validate(copy(self._data), context=context)
            except Exception as exc:  # noqa: BLE001 - candidate probing requires broad capture
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
        del context
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
        del context
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
        del context
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
        return content

    def update_session(
        self,
        *,
        include: Sequence[str] | None = None,
        exclude: Sequence[str] | None = None,
    ) -> None:
        del include, exclude
        if self._response is not None:
            self._cookies.model_validate_from_response(self.response)
            self._settings.model_validate_from_response(self.response)

    async def send_request(self, client: httpx.AsyncClient | None = None) -> httpx.Response:
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
        del include, exclude, exclude_unset, exclude_defaults, context

        body = self.request.body
        if (json_data := body.json_data) is not None:
            if content is None:
                content = {}
            if not isinstance(content, dict):
                raise TypeError("Content must be a dictionary.")
            content.update(json_data)
            return content
        return body.content

    async def __aexit__(self, exc_type, exc, tb):
        self.update_session()
        await super().__aexit__(exc_type, exc, tb)


__all__ = [
    "BaseTransport",
    "OAuthTransport",
]
