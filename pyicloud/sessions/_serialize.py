from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass, field, fields
from functools import WRAPPER_ASSIGNMENTS
from typing import Any, Literal, ParamSpec, Self, TypedDict, TypeVar, cast, overload

from pyicloud.models import _init_context_var
from pyicloud.paths import CookiesJar, SettingsFile

from ._transport import BaseTransport

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


class SerializeRuntimeInfo(TypedDict, total=False):
    settings: Serialize | dict[str, Any]
    cookies: Serialize | dict[str, Any]


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


def _resolve_runtime_serialize_info(context_data: object) -> SerializeRuntimeInfo:
    if not isinstance(context_data, dict):
        return {}
    runtime_data = context_data.get("serialize_info", {})
    if isinstance(runtime_data, dict):
        return cast(SerializeRuntimeInfo, runtime_data)
    return {}


def _configure_serialize_wrapper_state(
    instance: BaseTransport,
    *,
    settings: Serialize | dict[str, Any] | None,
    cookies: Serialize | dict[str, Any] | None,
) -> None:
    instance._serialize_settings_ = _normalize_serialize_config(
        settings,
        default=_default_serialize_settings(),
    )
    instance._serialize_cookies_ = _normalize_serialize_config(
        cookies,
        default=_default_serialize_cookies(),
    )

    runtime_serialize_info = _resolve_runtime_serialize_info(_init_context_var.get())
    instance._serialize_settings_ = _normalize_serialize_config(
        runtime_serialize_info.get("settings"),
        default=instance._serialize_settings_,
    )
    instance._serialize_cookies_ = _normalize_serialize_config(
        runtime_serialize_info.get("cookies"),
        default=instance._serialize_cookies_,
    )


async def _wrapper_aenter(wrapper_cls: type[Any], instance: BaseTransport):
    if instance._serialize_settings_.read:
        SettingsFile(instance._settings).loads()
    if instance._serialize_cookies_.read and (username := instance._settings.account.username):
        CookiesJar(instance._cookies).loads(username=username)
    return await super(wrapper_cls, instance).__aenter__()


async def _wrapper_aexit(wrapper_cls: type[Any], instance: BaseTransport, exc_type, exc, tb):
    result = await super(wrapper_cls, instance).__aexit__(exc_type, exc, tb)

    if instance._serialize_settings_.write:
        SettingsFile(instance._settings).saves(**instance._serialize_settings_.options.to_dict())
    if instance._serialize_cookies_.write:
        username = instance._settings.account.username
        if not username:
            raise ValueError("Cannot serialize cookies without an account username.")
        CookiesJar(instance._cookies).saves(
            username=username,
            **instance._serialize_cookies_.options.to_dict(),
        )
    return result


def _build_serialize_wrapper_class[BTTransport: BaseTransport](
    cls: type[BTTransport],
    *,
    settings: Serialize | dict[str, Any] | None,
    cookies: Serialize | dict[str, Any] | None,
) -> type[BTTransport]:
    if not issubclass(cls, BaseTransport):
        raise TypeError("serialize decorator only supports BaseTransport subclasses")

    class Wrapper(cls):
        def __init__(self, *args, **kwargs):
            _configure_serialize_wrapper_state(self, settings=settings, cookies=cookies)
            super().__init__(*args, **kwargs)

        async def __aenter__(self):
            return await _wrapper_aenter(Wrapper, self)

        async def __aexit__(self, exc_type, exc, tb):
            return await _wrapper_aexit(Wrapper, self, exc_type, exc, tb)

    for attr in WRAPPER_ASSIGNMENTS:
        setattr(Wrapper, attr, getattr(cls, attr))

    return cast(type[BTTransport], Wrapper)


def _build_serialize_decorator(
    *,
    settings: Serialize | dict[str, Any] | None,
    cookies: Serialize | dict[str, Any] | None,
) -> Callable[[type[BT]], type[BT]]:
    def decorator(cls: type[BT]) -> type[BT]:
        return _build_serialize_wrapper_class(cls, settings=settings, cookies=cookies)

    return decorator


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
    """Load and store settings/cookies around transport context management."""
    if cls is None:
        return _build_serialize_decorator(settings=settings, cookies=cookies)
    if not isinstance(cls, type):
        raise TypeError("cls must be a class")
    return _build_serialize_wrapper_class(cls, settings=settings, cookies=cookies)


__all__ = [
    "BaseSerialize",
    "IncEx",
    "SerializationInfo",
    "Serialize",
    "serialize",
]
