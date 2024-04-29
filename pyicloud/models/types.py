from __future__ import annotations

import re
from abc import ABC, abstractmethod
from functools import lru_cache
from typing import (
    Annotated,
    Any,
    ClassVar,
    Iterator,
    Literal,
    Mapping,
    Self,
    Sequence,
    TypeAlias,
    cast,
    get_args,
)

from psygnal import EventedModel
from pydantic import (
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)
from pydantic.dataclasses import dataclass
from pydantic.fields import FieldInfo
from pydantic.functional_validators import ModelWrapValidatorHandler

from pyicloud.constants import (
    ISO_639_1_CODES,
    ISO_3166_1_CODES,
    ISO_3166_1_CODES_3,
)
from pyicloud.constants import AppleCookies as Cookies
from pyicloud.constants import AppleHeaders as Headers
from pyicloud.models.morsel import MorselModel


@dataclass(config=ConfigDict(extra="forbid", frozen=True))
class Meta:
    header: str | None = None
    config: str | None = None
    cookie: str | None = None

    def __iter__(self) -> Iterator[tuple[str, str]]:
        if self.header is not None:
            yield "header", self.header
        if self.config is not None:
            yield "config", self.config
        if self.cookie is not None:
            yield "cookie", self.cookie

    def __hash__(self) -> int:
        return hash(tuple(v for _, v in self))

    @lru_cache
    @staticmethod
    def as_header(header: str) -> str:
        header = header.replace("_", "-")
        return "".join(word.lower() for word in re.split("-+", header))

    @lru_cache
    @staticmethod
    def as_cookie(cookie: str) -> str:
        return cookie.replace("_", "-").upper()

    @staticmethod
    def model_dump_meta(
        obj: Any,
        *,
        by_meta: Literal["header", "config", "cookie"],
        include: Sequence | None = None,
        exclude: Sequence | None = None,
        exclude_unset: bool = True,
        exclude_defaults: bool = False,
        exclude_none: bool = True,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        data = data or {}
        if hasattr(obj, "model_fields"):
            for name, info in cast(Mapping[str, FieldInfo], obj.model_fields).items():
                child = getattr(obj, name)
                if hasattr(child, "model_fields"):
                    data = Meta.model_dump_meta(
                        child,
                        by_meta=by_meta,
                        include=include,
                        exclude=exclude,
                        exclude_unset=exclude_unset,
                        exclude_defaults=exclude_defaults,
                        exclude_none=exclude_none,
                        data=data,
                    )
                    continue
                # Chekc if field satisfieds inclusion requirements
                default = info.get_default(call_default_factory=True)
                current = getattr(obj, name)
                isunset = not hasattr(obj, "model_fields_set") or name not in obj.model_fields_set
                if not info.is_required():
                    if exclude_defaults and current == default:
                        continue
                    if exclude_none and current is None:
                        continue
                    if exclude_unset and isunset:
                        continue
                # Extract metadata. Pydantic doesn't like unions outside of Annotated
                if not (metadata := info.metadata):
                    try:
                        metadata = cast(Any, info.annotation).__args__[0].__metadata__
                    except AttributeError:
                        metadata = []
                if meta := next((x for x in metadata if isinstance(x, Meta)), None):
                    if target := getattr(meta, by_meta):
                        if include and not (target in include or name in include):
                            continue
                        if exclude and (target in exclude or name in exclude):
                            continue
                        assert target not in data, f"Duplicate key {target} from {obj} found in data"
                        # Set data in flattered space
                        data[target] = current.get_secret_value() if hasattr(current, "get_secret_value") else current
        return data


# Header and config types always use standard Python types. Cookies, on the other hand,
# expect a Morsel due to its richer content.
#
# Config Types:
TimeZoneType: TypeAlias = Annotated[str, Meta(config="client_settings.timezone")]
ClientIdType: TypeAlias = Annotated[str, Meta(config="client_settings.client_id")]

# Headers - Config types:
CountryCodeType: TypeAlias = Annotated[
    str,
    Meta(header=Headers.COUNTRY_CODE, config="account.country_code"),
    StringConstraints(min_length=3, max_length=3),
]
SessionIdType: TypeAlias = Annotated[str, Meta(header=Headers.SESSION_ID, config="account.session_id")]
SessionTokenType: TypeAlias = Annotated[str, Meta(header=Headers.SESSION_TOKEN, config="token.session")]
TrustTokenType: TypeAlias = Annotated[str, Meta(header=Headers.TRUST_TOKEN, config="token.trust")]
ScntType: TypeAlias = Annotated[str, Meta(header=Headers.SCNT, config="client_settings.scnt")]


# Cookies - Config types:
DslangType: TypeAlias = Annotated[
    str | MorselModel,
    Meta(cookie=Cookies.DSLANG, config="session.dslang"),
    StringConstraints(min_length=5, max_length=5),
]
SiteType: TypeAlias = Annotated[
    str | MorselModel,
    Meta(cookie=Cookies.SITE, config="session.site"),
    StringConstraints(min_length=3, max_length=3),
]
# Cookie types:
AaspType: TypeAlias = Annotated[MorselModel, Meta(cookie=Cookies.AASP)]
Acn01Type: TypeAlias = Annotated[MorselModel, Meta(cookie=Cookies.ACN01)]
XAppleDsWebSessionTokenType: TypeAlias = Annotated[MorselModel, Meta(cookie=Cookies.WEB_SESSION_TOKEN)]
XAppleUniqueClientIdType: TypeAlias = Annotated[MorselModel, Meta(cookie=Cookies.CLIENT_ID)]
XAppleWebauthLoginType: TypeAlias = Annotated[MorselModel, Meta(cookie=Cookies.WEBAUTH_LOGIN)]
XAppleWebauthUserType: TypeAlias = Annotated[MorselModel, Meta(cookie=Cookies.WEBAUTH_USER)]
XAppleWebauthValidateType: TypeAlias = Annotated[MorselModel, Meta(cookie=Cookies.WEBAUTH_VALIDATE)]
XAppleWebauthHsaLoginType: TypeAlias = Annotated[MorselModel, Meta(cookie=Cookies.WEBAUTH_HSA_LOGIN)]
XAppleWebauthFmipType: TypeAlias = Annotated[MorselModel, Meta(cookie=Cookies.WEBAUTH_FMIP)]
XAppleWebauthHsaTrustType: TypeAlias = Annotated[MorselModel, Meta(cookie=Cookies.WEBAUTH_HSA_TRUST)]
XAppleWebauthTokenType: TypeAlias = Annotated[MorselModel, Meta(cookie=Cookies.WEBAUTH_TOKEN)]


class LeafModel(EventedModel, ABC):
    def __getitem__(self, name: str) -> Any:
        return getattr(self, name)

    def __setitem__(self, name: str, value: Any):
        setattr(self, name, value)

    def __contains__(self, name: str) -> bool:
        try:
            self.__getitem__(name)
            return True
        except AttributeError:
            return False

    def __delitem__(self, name: str):
        raise NotImplementedError

    @model_validator(mode="wrap")
    @classmethod
    def _wrap(
        cls,
        data: dict[str, Any],
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        fields_set = set()

        for field, info in cls.model_fields.items():
            if field in data:
                continue
            if not info.is_required():
                continue
            field_type = get_args(info.annotation) or (info.annotation,)
            if type(info.default) in field_type or info.default_factory:
                continue
            if factory_method := getattr(cls, f"{field}_default", None):
                data[field] = factory_method()
                fields_set.add(field)
                continue
        # Remove our created defaults from the model_fields_set
        retval = handler(data)
        retval.model_fields_set.difference_update(fields_set)
        return retval


class NestedModel(LeafModel):
    separator: ClassVar[str] = "."

    def __getitem__(self, name: str):
        def deep_getattr(model, key, sep="."):
            if sep in key:
                key, child_key = key.split(sep, 1)
                return deep_getattr(getattr(model, key), child_key, sep)
            return getattr(model, key)

        # Recursively get the attribute
        return deep_getattr(self, name, self.__class__.separator)

    def __setitem__(self, name: str, value):
        def deep_setattr(model, key, value, sep="."):
            if sep in key:
                key, child_key = key.split(sep, 1)
                deep_setattr(getattr(model, key), child_key, value, sep)
                return
            setattr(model, key, value)

        # Recursively set the attribute
        deep_setattr(self, name, value, self.__class__.separator)


class InitAbstractModel(LeafModel, ABC):
    model_config = ConfigDict(extra="forbid")

    dslang: DslangType = Field(default=...)
    site: SiteType = Field(default=...)

    @classmethod
    @abstractmethod
    def dslang_default(cls) -> DslangType: ...

    @field_validator("dslang")
    @classmethod
    def dslang_validate(cls, v: MorselModel | str) -> DslangType:
        dslang = v if isinstance(v, str) else v.value
        country, language = re.split("-|_", dslang.upper())
        if country not in ISO_3166_1_CODES:
            raise ValueError(f"Invalid country, {country}, expected ISO 3166-1 2 letter code")
        if language not in ISO_639_1_CODES:
            raise ValueError(f"Invalid language, {language}, expected ISO 639-1 code")
        return v

    @classmethod
    @abstractmethod
    def site_default(cls) -> SiteType: ...

    @field_validator("site")
    def validate_site_validate(cls, v: MorselModel | str) -> SiteType:
        site = v.upper() if isinstance(v, str) else v.value.upper()
        if site not in ISO_3166_1_CODES_3:
            raise ValueError(f"Invalid site {site}, expected ISO 3166-1 3 letter code")
        return v
