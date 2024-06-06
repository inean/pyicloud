from __future__ import annotations

import bisect
import locale
import uuid
from typing import (
    Any,
    ClassVar,
    Generic,
    Protocol,
    Self,
    Sequence,
    Type,
    TypedDict,
    TypeVar,
)

import tzlocal
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationInfo,
    model_validator,
)
from pydantic_settings import BaseSettings as PydanticSettings
from pydantic_settings import SettingsConfigDict

from pyicloud.constants import ISO_3166_1_CODES, ISO_3166_1_CODES_3
from pyicloud.models.types import (
    ClientIdType,
    CountryCodeType,
    DslangType,
    LeafModel,
    Meta,
    MetaFields,
    NestedModel,
    PasswordType,
    ScntType,
    SessionIdType,
    SessionTokenType,
    SiteType,
    TimeZone,
    TimeZoneType,
    TrustTokenType,
    UsernameType,
)
from pyicloud.utils.decorators import classproperty


class Account(LeafModel, validate_assignment=True):
    model_config = ConfigDict(populate_by_name=True)

    username: UsernameType
    password: PasswordType | None = None
    country_code: CountryCodeType = Field(default=...)
    session_id: SessionIdType | None = None
    with_family: bool = True

    @classmethod
    def country_code_default(cls):
        return "USA"


class Token(LeafModel):
    model_config = ConfigDict(populate_by_name=True)

    session: SessionTokenType = Field(
        default=None,
        serialization_alias="sessionToken",
    )
    trust: TrustTokenType = Field(
        default=None,
        serialization_alias="trustToken",
    )


class ClientSettings(LeafModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    dslang: DslangType = Field(default=...)
    site: SiteType = Field(default=...)
    timezone: TimeZoneType = Field(default=...)
    client_id: ClientIdType = Field(default_factory=lambda: f"auth-{str(uuid.uuid4()).lower()}")
    scnt: ScntType | None = None

    @classmethod
    def dslang_default(cls):
        locale_code = locale.getlocale()[0] or "en_US"
        return f"{locale_code[3:]}-{locale_code[:2].upper()}"

    @classmethod
    def site_default(cls):
        locale_code = locale.getlocale()[0] or "en_US"
        alpha3166_3 = bisect.bisect_left(ISO_3166_1_CODES, locale_code[3:])
        return ISO_3166_1_CODES_3[alpha3166_3]

    @classmethod
    def timezone_default(cls) -> TimeZone:
        return TimeZone(tzlocal.get_localzone_name())

    @property
    def timezone_offset(self) -> str:
        return self.timezone.offset()


class ResponseModel(Protocol):
    headers: BaseModel
    cookies: BaseModel


A = TypeVar("A", bound=Account)
T = TypeVar("T", bound=Token)
C = TypeVar("C", bound=ClientSettings)


class SettingsConfig(TypedDict, Generic[A, T, C], total=False):
    account: type[A]
    token: type[T]
    client_settings: type[C]


class BaseSettings(NestedModel, PydanticSettings, Generic[A, T, C]):
    model_config = SettingsConfigDict(
        validate_default=False,
        env_prefix="PYICLOUD",
    )

    _config_settings: ClassVar[SettingsConfig] = SettingsConfig(
        account=Account,
        token=Token,
        client_settings=ClientSettings,
    )

    account: A
    token: T = Field(default=...)
    client_settings: C = Field(default=...)

    @classmethod
    def __pydantic_init_subclass__(cls, **kwargs):
        # Update config with default values for bae class
        new_config = SettingsConfig(
            account=Account,
            token=Token,
            client_settings=ClientSettings,
        )
        new_config.update(cls._config_settings)
        cls._config_settings = new_config

    @model_validator(mode="before")
    @classmethod
    def fill_defaults(cls, data: dict[str, Any], info: ValidationInfo) -> dict[str, Any]:
        assert isinstance(data, dict)
        for f_name, f_value in cls._config_settings.items():
            if f_name not in cls.model_fields:
                continue
            if f_name not in data and isinstance(f_value, type) and issubclass(f_value, BaseModel):
                # If default value is the same that the annotation, update it.
                # We can use None becouse pydantic use PydanticUndefined
                # Use model_validate instead of cosntruct to properly build event subsystem
                data[f_name] = f_value.model_validate({})
        return data

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

    def model_dump_by_meta(
        self,
        *,
        by_meta: MetaFields = "header",
        include: Sequence[str] | None = None,
        exclude: Sequence[str] | None = None,
        exclude_unset=True,
        exclude_defaults=False,
    ) -> dict[str, Any]:
        return Meta.model_dump_meta(
            self,
            by_meta=by_meta,
            include=include,
            exclude=exclude,
            exclude_unset=exclude_unset,
            exclude_defaults=exclude_defaults,
        )

    def model_validate_from_response(
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

    @classproperty
    def Account(cls) -> type[Account]:
        return cls._config_settings.get("account", Account)

    @classproperty
    def Token(cls) -> type[Token]:
        return cls._config_settings.get("token", Token)

    @classproperty
    def ClientSettings(cls) -> Type[ClientSettings]:
        return cls._config_settings.get("client_settings", ClientSettings)


class Settings(BaseSettings[Account, Token, ClientSettings]):
    """Update the settings with the result data."""

    def model_dump_json(self, **kwargs) -> str:
        kwargs.setdefault("by_alias", True)
        return super().model_dump_json(**kwargs)
