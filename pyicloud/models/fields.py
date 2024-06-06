from __future__ import annotations

import datetime
import re
import zoneinfo
from http.cookiejar import Cookie, CookieJar
from http.cookies import BaseCookie, Morsel, _quote
from time import time
from typing import (
    Annotated,
    Any,
    Sequence,
    TypeAlias,
    cast,
)
from uuid import UUID

import httpx
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    GetCoreSchemaHandler,
    PlainSerializer,
    SecretStr,
    StringConstraints,
    WithJsonSchema,
    field_validator,
    model_validator,
)
from pydantic.types import UuidVersion
from pydantic_core import PydanticCustomError, core_schema

from pyicloud.constants import (
    ISO_639_1_CODES,
    ISO_3166_1_CODES,
    ISO_3166_1_CODES_3,
)
from pyicloud.constants import AppleCookies as Cookies
from pyicloud.constants import AppleHeaders as Header
from pyicloud.models import Meta

# Header Types:
RequestIdType: TypeAlias = Annotated[UUID, UuidVersion(1), Meta(header=Header.REQUEST_ID)]
TrustTokenEligibleType: TypeAlias = Annotated[bool, Meta(header=Header.TRUST_TOKEN_ELIGIBLE)]
AuthAttributesType: TypeAlias = Annotated[str, Meta(header=Header.AUTH_ATTRIBUTES)]
OAuthGrantCodeType: TypeAlias = Annotated[str, Meta(header=Header.OAUTH_GRANT_CODE)]


# Header and config types always use standard Python types. Cookies, on the other hand,
# expect a Morsel due to its richer content.
#
# Config Types:


class TimeZone(str):
    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        source: type[Any],
        handler: GetCoreSchemaHandler,
    ) -> core_schema.CoreSchema:
        return core_schema.with_info_after_validator_function(
            cls._validate,
            core_schema.str_schema(),
        )

    @classmethod
    def _validate(cls, __input_value: str, _: Any) -> TimeZone:
        try:
            zoneinfo.ZoneInfo(__input_value)
        except zoneinfo.ZoneInfoNotFoundError as err:
            raise PydanticCustomError(
                "invalid_timezone",
                f"Invalid timezone {__input_value}",  # type: ignore
            ) from err
        return cls(__input_value)

    def offset(self, date: datetime.datetime | None = None) -> str:
        zone = zoneinfo.ZoneInfo(self)
        # compute the time offset
        time_offset = zone.utcoffset(date or datetime.datetime.now())
        time_offset = time_offset.seconds if time_offset else 0
        # convert to hours and minutes in GMT format
        hrs = int(time_offset // (60 * 60))
        min = abs(time_offset % (60 * 60))

        return f"GMT{hrs:+03d}:{min:02d}"


TimeZoneType: TypeAlias = Annotated[TimeZone, Meta(config="client_settings.timezone")]


def validate_email(v: str) -> str:
    if not re.match(r"[^@]+@[^@]+\.[^@]+", v):
        raise PydanticCustomError("invalid_email", f"Invalid email address. Got '{v}'")  # type: ignore
    return v


UsernameType: TypeAlias = Annotated[
    str,
    BeforeValidator(validate_email),
    Meta(config="account.username", body="accountName"),
]
PasswordType: TypeAlias = Annotated[
    SecretStr,
    PlainSerializer(
        lambda v: cast(SecretStr, v).get_secret_value() if v else None, return_type=str | None, when_used="json"
    ),
    Meta(config="account.password", body="password"),
]


# Headers - Config types:
def country_code_must_be_iso_3166_3(v: str) -> str:
    if v is not None:
        country = v.upper()
        if country not in ISO_3166_1_CODES_3:
            raise ValueError(f"Invalid site {country}, expected ISO 3166-1 3 letter code")
    return v


CountryCodeType: TypeAlias = Annotated[
    str,
    BeforeValidator(country_code_must_be_iso_3166_3),
    Meta(header=Header.COUNTRY_CODE, config="account.country_code"),
    StringConstraints(min_length=3, max_length=3),
]
ClientIdType: TypeAlias = Annotated[str, Meta(header=Header.OAUTH_STATE, config="client_settings.client_id")]
SessionIdType: TypeAlias = Annotated[str, Meta(header=Header.SESSION_ID, config="account.session_id")]
SessionTokenType: TypeAlias = Annotated[str, Meta(header=Header.SESSION_TOKEN, config="token.session")]
ScntType: TypeAlias = Annotated[str, Meta(header=Header.SCNT, config="client_settings.scnt")]

TrustTokenType = Annotated[
    str | None,
    BeforeValidator(lambda v: v if isinstance(v, str) else v[0] if isinstance(v, Sequence) else None),
    PlainSerializer(lambda v: [v] if v else [], return_type=list[str], when_used="json"),
    WithJsonSchema(
        {"anyOf": [{"items": {"type": "string"}, "type": "array"}, {"type": "string"}, {"type": "null"}]},
        mode="validation",
    ),
    WithJsonSchema({"items": {"type": "string"}, "type": "array"}, mode="serialization"),
    Meta(header=Header.TRUST_TOKEN, config="token.trust", body="trustTokens"),
]


# Cookies - Config types: Default values are only set on config classes.
def dslang_validate(v: MorselModel | str) -> str:
    dslang = v if isinstance(v, str) else v.value
    country, language = dslang.split("-")
    if country not in ISO_3166_1_CODES:
        raise ValueError(f"Invalid country, {country}, expected ISO 3166-1 2 letter code")
    if language not in ISO_639_1_CODES:
        raise ValueError(f"Invalid language, {language}, expected ISO 639-1 code")
    return dslang


DslangType: TypeAlias = Annotated[
    str,
    BeforeValidator(dslang_validate),
    Meta(cookie=Cookies.DSLANG, config="client_settings.dslang"),
    StringConstraints(min_length=5, max_length=5),
]


def site_validate(v: MorselModel | str) -> SiteType:
    site = v.upper() if isinstance(v, str) else v.value.upper()
    if site not in ISO_3166_1_CODES_3:
        raise ValueError(f"Invalid site {site}, expected ISO 3166-1 3 letter code")
    return site


SiteType: TypeAlias = Annotated[
    str,
    Meta(cookie=Cookies.SITE, config="client_settings.site"),
    StringConstraints(min_length=3, max_length=3),
]
# Cookie types:


# Extend Morsel reserved keywords to support missing attributes:
cast(dict, Morsel._reserved).update(  # type: ignore
    path_spec="path_spec",
    discard="discard",
    version="version",
    domain_dot="domain_dot",
)
cast(set, Morsel._flags).update(["path_spec", "discard", "domain_dot"])  # type: ignore


JarTypes: TypeAlias = dict[str, Morsel] | httpx.Cookies | CookieJar | Sequence
JarTuple = (dict, httpx.Cookies, CookieJar, Sequence)


class MorselModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    key: str = Field(..., alias="name")
    value: str = Field(...)
    expires: int | None = None
    path: str = Field(default="/")
    comment: str | None = None
    domain: str = Field(default="")
    max_age: float | None = Field(default=None, alias="max-age")
    secure: bool | None = None
    httponly: bool | None = None
    domain_dot: bool | None = None
    discard: bool | None = None
    path_spec: bool | None = None
    samesite: str | None = None
    version: int = 0

    @field_validator("expires", mode="before")
    def validate_expires(cls, value: int | str | datetime.datetime) -> int | None:
        if isinstance(value, str):
            return int(datetime.datetime.fromisoformat(value).timestamp())
        if isinstance(value, datetime.datetime):
            return int(value.timestamp())
        return value

    @model_validator(mode="before")
    def extract_from_morsel_or_cookie(cls, data: Cookie | Morsel | str | dict[str, Any]) -> Any:
        cookie = data
        if isinstance(data, str):
            # Define los atributos no soportados
            unsupported_attributes = [
                "path_spec",
            ]
            # Crea una expresión regular para buscar los atributos no soportados
            regex = "|".join(f"{attr}=[^;]*" for attr in unsupported_attributes)
            cleaned_data = re.sub(regex, "", data)
            jar = BaseCookie()
            jar.load(cleaned_data)
            if len(jar) != 1:
                raise ValueError(f"Invalid cookie string: {cleaned_data}")

            cookie = next(iter(jar.values()))

        if isinstance(cookie, Cookie):
            data = dict(
                name=cookie.name,
                value=cookie.value,
                path=cookie.path,
                domain=cookie.domain,
                expires=cookie.expires,
                comment=cookie.comment,
                version=cookie.version,
                path_spec=cookie.path_specified,
                discard=cookie.discard,
                max_age=cookie.expires - time() if cookie.expires else None,
                secure=cookie.secure,
                httponly=cookie.get_nonstandard_attr("httponly"),
                samesite=cookie.get_nonstandard_attr("samesite"),
                domain_dot=cookie.get_nonstandard_attr("domain_dot"),
            )

        if isinstance(cookie, Morsel):
            data = dict(
                key=cookie.key,
                value=cookie.value,
                path=cookie.get("path"),
                domain=cookie.get("domain"),
                expires=cookie.get("expires"),
                comment=cookie.get("comment"),
                max_age=cookie.get("max-age"),
                secure=cookie.get("secure"),
                httponly=cookie.get("httponly"),
                samesite=cookie.get("samesite"),
                version=cookie.get("version", None),
                path_spec=cookie.get("path_spec", None),
                discard=cookie.get("discard", None),
                domain_dot=cookie.get("domain_dot", None),
            )
        assert isinstance(data, dict)

        # Remove None or empty '' values
        return {k: v for k, v in data.items() if v is not None and v != ""}

    def __len__(self) -> int:
        return len(self.value)

    def __cast__(self, cast_to: Any) -> Any:
        if cast_to in (str, int, float, bool):
            return cast_to(self.value)
        raise TypeError(f"Cannot cast {self.__class__.__name__} to {type}")

    def is_expired(self) -> bool:
        return bool(self.expires and self.expires < time())

    def model_dump_str(self, attrs=None, header="Set-Cookie:") -> str:
        morsel, values = Morsel(), self.model_dump(by_alias=True)
        morsel.set(values.pop("name"), values.pop("value"), _quote(self.value))
        morsel.update(values)
        return morsel.output(attrs, header)

    def model_dump_cookie(self) -> Cookie:
        kwargs = {
            "version": self.version,
            "name": self.key,
            "value": self.value,
            "port": None,
            "port_specified": False,
            "domain": self.domain,
            "domain_specified": bool(self.domain),
            "domain_initial_dot": isinstance(self.domain, str) and self.domain.startswith("."),
            "path": self.path,
            "path_specified": bool(self.path),
            "secure": self.secure,
            "expires": self.expires,
            "discard": self.discard,
            "comment": self.comment,
            "comment_url": None,
            "rest": {"HttpOnly": self.httponly},
            "rfc2109": False,
        }
        return Cookie(**kwargs)

    @classmethod
    def as_cookie(cls, data: dict[str, Any]) -> Cookie:
        return cls(**data).model_dump_cookie()

    @classmethod
    def from_jar(cls, cookie_name: str, jar: JarTypes) -> MorselModel | None:
        if isinstance(jar, dict):
            if cookie := jar.get(cookie_name):
                # dict[str, Morsel] Path
                if isinstance(cookie, Morsel):
                    return cls.model_validate(cookie)
                # dict[str, dict[str, str]] Path
                if isinstance(cookie, dict):
                    return cls(**cookie)
        # CookieJar and Cookie Path
        if isinstance(jar, httpx.Cookies):
            jar = jar.jar
        if isinstance(jar, CookieJar):
            if cookie := next(filter(lambda c: c.name == cookie_name, jar), None):
                return cls.model_validate(cookie)


DslangCookieType: TypeAlias = Annotated[MorselModel, Meta(cookie=Cookies.DSLANG, config="client_settings.dslang")]
SiteCookieType: TypeAlias = Annotated[MorselModel, Meta(cookie=Cookies.SITE, config="client_settings.site")]
AaspType: TypeAlias = Annotated[MorselModel, Meta(cookie=Cookies.AASP)]
Acn01Type: TypeAlias = Annotated[MorselModel, Meta(cookie=Cookies.ACN01)]
DesType: TypeAlias = Annotated[MorselModel, Meta(cookie=Cookies.DES_PATTERN)]
XAppleDsWebSessionTokenType: TypeAlias = Annotated[MorselModel, Meta(cookie=Cookies.WEB_SESSION_TOKEN)]
XAppleUniqueClientIdType: TypeAlias = Annotated[MorselModel, Meta(cookie=Cookies.CLIENT_ID)]
XAppleWebauthLoginType: TypeAlias = Annotated[MorselModel, Meta(cookie=Cookies.WEBAUTH_LOGIN)]
XAppleWebauthUserType: TypeAlias = Annotated[MorselModel, Meta(cookie=Cookies.WEBAUTH_USER)]
XAppleWebauthValidateType: TypeAlias = Annotated[MorselModel, Meta(cookie=Cookies.WEBAUTH_VALIDATE)]
XAppleWebauthHsaLoginType: TypeAlias = Annotated[MorselModel, Meta(cookie=Cookies.WEBAUTH_HSA_LOGIN)]
XAppleWebauthFmipType: TypeAlias = Annotated[MorselModel, Meta(cookie=Cookies.WEBAUTH_FMIP)]
XAppleWebauthHsaTrustType: TypeAlias = Annotated[MorselModel, Meta(cookie=Cookies.WEBAUTH_HSA_TRUST)]
XAppleWebauthTokenType: TypeAlias = Annotated[MorselModel, Meta(cookie=Cookies.WEBAUTH_TOKEN)]
