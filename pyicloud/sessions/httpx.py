from __future__ import annotations

from functools import WRAPPER_ASSIGNMENTS
from typing import (
    Any,
    Callable,
    NamedTuple,
    ParamSpec,
    Protocol,
    Type,
    TypeVar,
    cast,
    overload,
)

import httpx

from pyicloud.paths import CookiesJar, SettingsFile
from pyicloud.sessions.base import BaseSession


class iAsyncClient(Protocol):
    @property
    def json_data(self) -> dict: ...

    @json_data.setter
    def json_data(self, value: dict) -> None: ...


T = TypeVar("T", bound=BaseSession)
P = ParamSpec("P")


def allow_verbs(*accepted_verbs: str):
    """Allow the given methods to be called without a valid session."""

    def build_request(self, method: str, url, *, json: Any = None, **kwargs) -> Any:
        json = json or self._json_data
        return self._build_request(method, url, json=json, **kwargs)

    class HttpxClientWrapper:
        def __init__(self, httpx: httpx.AsyncClient) -> None:
            self._httpx = httpx

            # MonkeyPatch: build_request method
            object.__setattr__(self._httpx, "_build_request", self._httpx.build_request)
            object.__setattr__(self._httpx, "build_request", build_request.__get__(self._httpx))

            # MonkeyPatch: Initialize json_data
            object.__setattr__(self._httpx, "_json_data", {})

        def __getattr__(self, name: str) -> Any:
            VERBS = ["get", "post", "put", "delete", "options", "head", "patch"]
            if name in VERBS and name not in accepted_verbs:
                raise NameError(f"Verb {name} is not allowed")
            return getattr(self._httpx, name)

        @property
        def json_data(self) -> dict:
            return self._httpx._json_data  # type: ignore

        @json_data.setter
        def json_data(self, value: dict) -> None:
            self._httpx._json_data = value  # type: ignore

    # Uncomment to make the wrapper look like the original httpx client
    #
    # for attr in WRAPPER_ASSIGNMENTS:
    #    setattr(ClientWrapper, attr, getattr(httpx.AsyncClient, attr))

    def decorator(cls: Type[T]) -> Type[T]:
        # Override constructor to wrap the httpx client
        original_init = cls.__init__

        def new_init(self: T, *args: P.args, **kwargs: P.kwargs):
            original_init(self, *args, **kwargs)  # type: ignore
            self._httpx = cast(httpx.AsyncClient, HttpxClientWrapper(self._httpx))

        cls.__init__ = new_init  # type: ignore
        return cls

    return decorator


class Serialize(NamedTuple):
    read: bool
    write: bool


@overload
def serialize(cls: Type[T]) -> Type[T]: ...


@overload
def serialize(
    *,
    settings_read: bool = True,
    settings_write: bool = True,
    cookies_read: bool = True,
    cookies_write: bool = True,
) -> Callable[[Type[T]], Type[T]]: ...


@overload
def serialize(
    cls: Type[T],
    *,
    settings_read: bool = True,
    settings_write: bool = True,
    cookies_read: bool = True,
    cookies_write: bool = True,
    dump_settings_options: dict[str, Any] | None = None,
    validate_settings_options: dict[str, Any] | None = None,
    dump_cookies_options: dict[str, Any] | None = None,
    validate_cookies_options: dict[str, Any] | None = None,
) -> Type[T]: ...


def serialize(
    cls: Type[T] | None = None,
    *,
    settings_read: bool = True,
    settings_write: bool = True,
    cookies_read: bool = True,
    cookies_write: bool = True,
    dump_settings_options: dict[str, Any] | None = None,
    validate_settings_options: dict[str, Any] | None = None,
    dump_cookies_options: dict[str, Any] | None = None,
    validate_cookies_options: dict[str, Any] | None = None,
    **kwargs,
) -> Type[T] | Callable[[Type[T]], Type[T]]:
    """Load and store session and cookies when entering and exiting the context manager."""

    # If no class is provided, return a decorator that will call configure with the provided class
    if cls is None:

        def decorator(cls: Type[T]) -> Type[T]:
            return serialize(
                cls,
                settings_read=settings_read,
                settings_write=settings_write,
                cookies_read=cookies_read,
                cookies_write=cookies_write,
                dump_settings_options=dump_settings_options,
                validate_settings_options=validate_settings_options,
                dump_cookies_options=dump_cookies_options,
                validate_cookies_options=validate_cookies_options,
            )

        return decorator

    # Check if cls is a class
    if not isinstance(cls, type):
        raise TypeError("cls must be a class")

    class Wrapper(cls):
        """New wrapper that will extend the wrapper `cls` to make it look like `wrapped`"""

        def __init__(self, *args, **kwargs):
            self._serialize_settings = Serialize(
                kwargs.get("settings_read", settings_read),
                kwargs.get("settings_write", settings_write),
            )
            self._serialize_cookies = Serialize(
                kwargs.get("cookies_read", cookies_read),
                kwargs.get("cookies_write", cookies_write),
            )

            # Serailization options for settings
            self._dump_settings_options = kwargs.get(
                "dump_settings_options",
                dump_settings_options,
            ) or {
                "by_alias": True,
                "exclude_none": True,
                "indent": 2,
            }
            self._validate_settings_options = kwargs.get("validate_settings_options", validate_settings_options) or {}

            # Serailization options for cookies
            self._dump_cookies_options = kwargs.get(
                "dump_cookies_options",
                dump_cookies_options,
            ) or {
                "by_alias": True,
                "exclude_defaults": True,
                "exclude_none": True,
                "exclude_unset": True,
                "indent": 2,
            }
            self._validate_cookies_options = kwargs.get("validate_cookies_options", validate_cookies_options) or {}
            # Call the original __init__ method
            super().__init__(*args, **kwargs)

        async def __aenter__(self: T):
            # Load session and cookies
            wrapper = cast(Wrapper, self)
            if wrapper._serialize_settings.read:
                SettingsFile(self._settings).loads(**(wrapper._validate_settings_options))
            if wrapper._serialize_cookies.read:
                if username := self._settings.account.username:
                    CookiesJar(self._cookies).loads(username=username, **wrapper._validate_cookies_options)
            return await super().__aenter__()

        async def __aexit__(self, exc_type, exc, tb):
            # Call the original __aexit__ method
            result = await super().__aexit__(exc_type, exc, tb)
            # Write session and cookies
            wrapper = cast(Wrapper, self)
            if wrapper._serialize_settings.write:
                SettingsFile(self._settings).saves(**wrapper._dump_settings_options)
            if wrapper._serialize_cookies.write:
                username = self._settings.account.username
                assert username
                CookiesJar(self._cookies).saves(username=username, **wrapper._dump_cookies_options)
            return result

    # Assign the attributes
    for attr in WRAPPER_ASSIGNMENTS:
        setattr(Wrapper, attr, getattr(cls, attr))

    return Wrapper  # type: ignore
