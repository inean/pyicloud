from __future__ import annotations

import datetime
import re
import uuid
import zoneinfo
from abc import ABC
from typing import Any, ClassVar, Generic, Protocol, Self, Sequence, Type, TypedDict, TypeVar, cast

import tzlocal
from pydantic import (
    BaseModel,
    Field,
    SecretStr,
    computed_field,
    field_serializer,
    field_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

from pyicloud.constants import ISO_3166_1_CODES_3
from pyicloud.models.types import (
    ClientIdType,
    CountryCodeType,
    InitAbstractModel,
    LeafModel,
    Meta,
    NestedModel,
    ScntType,
    SessionIdType,
    SessionTokenType,
    TimeZoneType,
    TrustTokenType,
)
from pyicloud.utils.decorators import classproperty


class Account(LeafModel, validate_assignment=True):
    username: str
    password: SecretStr | str | None = Field(default=None)
    country_code: CountryCodeType = Field(default=...)
    session_id: SessionIdType | None = None
    with_family: bool = True

    @field_validator("username")
    def username_must_be_email(cls, v: str):
        # Apple ID must be a valid email or an empty string
        if not re.match(r"[^@]+@[^@]+\.[^@]+", v):
            raise ValueError("username must be a valid email")
        return v

    @classmethod
    def country_code_default(cls):
        return "USA"

    @field_validator("country_code")
    def country_code_must_be_iso_3166_3(cls, v: CountryCodeType) -> CountryCodeType:
        if v is not None:
            country = v.upper()
            if country not in ISO_3166_1_CODES_3:
                raise ValueError(f"Invalid site {country}, expected ISO 3166-1 3 letter code")
        return v

    @field_validator("password")
    def password_must_be_secret(cls, v: SecretStr | str | None) -> SecretStr | None:
        if isinstance(v, str):
            return SecretStr(v)
        return v

    @field_serializer("password", when_used="json")
    def dump_secret(self, v: SecretStr | None) -> str | None:
        return v.get_secret_value() if v else None


class Token(LeafModel):
    session: SessionTokenType = Field(
        default=None,
        serialization_alias="sessionToken",
    )
    trust: TrustTokenType = Field(
        default=None,
        serialization_alias="trustToken",
    )


class ClientSettings(InitAbstractModel):
    timezone: TimeZoneType = Field(default=...)
    client_id: ClientIdType = Field(default_factory=lambda: f"auth-{str(uuid.uuid4()).lower()}")
    scnt: ScntType | None = None

    @classmethod
    def timezone_default(cls):
        return tzlocal.get_localzone_name()

    @field_validator("timezone")
    def validate_timezone(cls, v: str) -> str:
        try:
            zoneinfo.ZoneInfo(v)
        except zoneinfo.ZoneInfoNotFoundError as err:
            raise ValueError(f"Invalid timezone {v}") from err
        return v

    @computed_field(alias="timeOffset")
    def time_offset(self) -> str:  # type: ignore
        zone = zoneinfo.ZoneInfo(self.timezone)
        # compute the time offset
        time_offset = zone.utcoffset(datetime.datetime.now())
        time_offset = time_offset.seconds if time_offset else 0
        # convert to hours and minutes in GMT format
        hrs = int(time_offset // (60 * 60))
        min = abs(time_offset % (60 * 60))
        return f"GMT{hrs:+03d}:{min:02d}"


class ResponseModel(Protocol):
    headers: BaseModel
    cookies: BaseModel


A = TypeVar("A", bound=Account)
T = TypeVar("T", bound=Token)
C = TypeVar("C", bound=ClientSettings)


class SettingsDict(TypedDict, Generic[A, T, C], total=False):
    account: type[A]
    token: type[T]
    client_settings: type[C]


class BaseSettings(NestedModel, BaseSettings, Generic[A, T, C]):
    model_config = SettingsConfigDict(
        validate_default=False,
        env_prefix="PYICLOUD",
    )

    account: A
    token: T = Field(default={})
    client_settings: C = Field(default={})

    @classmethod
    def __pydantic_init_subclass__(cls, **kwargs):
        # Update config with default values for bae class
        new_config = SettingsDict(
            account=Account,
            token=Token,
            client_settings=ClientSettings,
        )
        new_config.update(cls.config_settings)
        cls.config_settings = new_config

        # Update model fields with annotations from config
        for f_name, f_value in cls.config_settings.items():
            if info := cls.model_fields.get(f_name):
                if callable(f_value):
                    # If default value is the same that the annotation, update it.
                    # We can use None becouse pydantic use PydanticUndefined
                    if hasattr(f_value, "model_validate") and isinstance(info.default, dict):
                        info.default = cast(Any, f_value).model_validate(info.default)
                # update the annotation with the new value
                info.annotation = f_value

    @classmethod
    def create(cls, username: str | None = None, password: str | None = None) -> Self:
        if username is not None:
            return cls(
                account=cls.Account(
                    username=username,
                    password=SecretStr(password) if password is not None else None,
                )
            )
        assert password is None, "Can't set password without username."
        return cls(account=cls.Account.model_construct())

    def __hash__(self) -> int:
        return id(self)

    def model_dump_headers(
        self,
        *,
        include: Sequence[str] | None = None,
        exclude: Sequence[str] | None = None,
        exclude_unset=True,
        exclude_defaults=False,
    ) -> dict[str, Any]:
        return Meta.model_dump_meta(
            self,
            by_meta="header",
            include=include,
            exclude=exclude,
            exclude_unset=exclude_unset,
            exclude_defaults=exclude_defaults,
        )

    def model_update(
        self,
        response: ResponseModel,
        *,
        include: Sequence[str] | None = None,
        exclude: Sequence[str] | None = None,
    ):
        """Create a response from a httpx response."""
        settings = Meta.model_dump_meta(
            response,
            by_meta="config",
            include=include,
            exclude=exclude,
            exclude_unset=True,
            exclude_defaults=True,
        )
        # Update settings with values from response
        for config_key, value in settings.items():
            self[config_key] = value

    config_settings: ClassVar[SettingsDict] = SettingsDict()

    @classproperty
    def Account(cls) -> type[Account]:
        return cls.config_settings.get("account", Account)

    @classproperty
    def Token(cls) -> type[Token]:
        return cls.config_settings.get("token", Token)

    @classproperty
    def ClientSettings(cls) -> Type[ClientSettings]:
        return cls.config_settings.get("client_settings", ClientSettings)


class Settings(BaseSettings[Account, Token, ClientSettings]):
    """Update the settings with the result data."""


class SettingsModel(BaseModel, ABC):
    """Update the settings with the result data."""
