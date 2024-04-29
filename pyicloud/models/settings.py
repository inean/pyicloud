from __future__ import annotations

import datetime
import re
import uuid
import zoneinfo
from typing import Any, ClassVar, Protocol, Self, Type, TypedDict

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


class Account(LeafModel, validate_assignment=True):
    username: str
    password: SecretStr | None = None
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

    @field_serializer("password", when_used="always")
    def dump_secret(self, v: SecretStr):
        return v.get_secret_value()


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

    @classmethod
    def dslang_default(cls):
        return "US-EN"

    @classmethod
    def site_default(cls):
        return "USA"

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
    cookies: BaseModel
    headers: BaseModel


class SettingsConfig(TypedDict, total=False):
    account: Type[Account]
    token: Type[Token]
    client_settings: Type[ClientSettings]


class Settings(NestedModel, BaseSettings):
    model_config = SettingsConfigDict(
        validate_default=False,
        env_prefix="PYICLOUD",
    )

    _config: ClassVar[SettingsConfig] = SettingsConfig(
        account=Account,
        token=Token,
        client_settings=ClientSettings,
    )
    account: Account
    token: Token = Token()
    client_settings: ClientSettings = ClientSettings()

    @classmethod
    def __pydantic_init_subclass__(cls, **kwargs):
        # Update config with default values for bae class
        new_config = SettingsConfig(
            account=Account,
            token=Token,
            client_settings=ClientSettings,
        )
        new_config.update(cls._config)
        cls._config = new_config

    @classmethod
    def create(cls, username: str | None = None) -> Self:
        return cls(
            account=cls._config["account"](username=username) if username else cls._config["account"].model_construct(),  # type: ignore
            token=cls._config["token"](),  # type: ignore
            client_settings=cls._config["client_settings"](),  # type: ignore
        )

    def __hash__(self) -> int:
        return id(self)

    def model_dump_headers(
        self, *, include=None, exclude=None, exclude_unset=True, exclude_defaults=False
    ) -> dict[str, Any]:
        return Meta.model_dump_meta(
            self,
            by_meta="header",
            include=include,
            exclude=exclude,
            exclude_unset=exclude_unset,
            exclude_defaults=exclude_defaults,
        )

    def model_update(self, response: ResponseModel, *, include=None, exclude=None):
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
