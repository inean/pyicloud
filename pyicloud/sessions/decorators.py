from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from functools import WRAPPER_ASSIGNMENTS
from typing import (
    Any,
    Callable,
    Literal,
    ParamSpec,
    Self,
    Type,
    TypeAlias,
    TypeVar,
    cast,
    overload,
)

from pyicloud.models.types import _init_context_var
from pyicloud.paths import CookiesJar, SettingsFile
from pyicloud.sessions.base import BaseTransport

T = TypeVar("T", bound=BaseTransport)
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
    read: bool = True
    write: bool = True
    options: SerializationInfo = field(default_factory=SerializationInfo)


@overload
def serialize(cls: Type[T]) -> Type[T]: ...


@overload
def serialize(
    cls: Type[T],
    *,
    settings: Serialize | dict[str, Any] | None = None,
    cookies: Serialize | dict[str, Any] | None = None,
) -> Type[T]: ...


def serialize(
    cls: Type[T] | None = None,
    *,
    settings: Serialize | dict[str, Any] | None = None,
    cookies: Serialize | dict[str, Any] | None = None,
) -> Type[T] | Callable[[Type[T]], Type[T]]:
    """Load and store session and cookies when entering and exiting the context manager."""

    # If no class is provided, return a decorator that will call configure with the provided class
    if cls is None:

        def decorator(cls: Type[T]) -> Type[T]:
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
            assert issubclass(cls, cast(Any, T.__bound__))

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

        async def __aenter__(self: T):
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
