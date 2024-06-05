from __future__ import annotations

import datetime
import re
import zoneinfo
from functools import lru_cache
from typing import (
    Annotated,
    Any,
    Callable,
    ClassVar,
    Collection,
    Iterator,
    Literal,
    Mapping,
    Self,
    Sequence,
    Tuple,
    TypeAlias,
    cast,
    get_args,
    get_origin,
    overload,
)
from uuid import UUID

from psygnal import EventedModel
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    GetCoreSchemaHandler,
    PlainSerializer,
    Secret,
    SerializationInfo,
    StringConstraints,
    WithJsonSchema,
    model_serializer,
    model_validator,
)
from pydantic.dataclasses import dataclass
from pydantic.fields import FieldInfo
from pydantic.functional_validators import ModelWrapValidatorHandler
from pydantic.types import UuidVersion
from pydantic_core import PydanticCustomError, core_schema

from pyicloud.constants import (
    ISO_639_1_CODES,
    ISO_3166_1_CODES,
    ISO_3166_1_CODES_3,
)
from pyicloud.constants import AppleCookies as Cookies
from pyicloud.constants import AppleHeaders as Header
from pyicloud.log import LOGGER
from pyicloud.models.morsel import MorselModel
from pyicloud.utils.context import _init_context_var

MetaFields: TypeAlias = Literal["header", "config", "cookie", "body", "params"]


@dataclass(config=ConfigDict(extra="forbid", frozen=True))
class Meta:
    header: str | None = None
    config: str | None = None
    cookie: str | None = None
    body: str | None = None
    params: str | None = None

    def __iter__(self) -> Iterator[tuple[str, str]]:
        for field in get_args(MetaFields):
            if getattr(self, field) is not None:
                yield field, getattr(self, field)

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
        by_meta: MetaFields,
        include: Sequence[str] | None = None,
        exclude: Sequence[str] | None = None,
        exclude_unset: bool = True,
        exclude_defaults: bool = False,
        exclude_none: bool = True,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        data = data or {}
        if hasattr(obj, "model_fields"):
            for name, info in cast(Mapping[str, FieldInfo], obj.model_fields).items():
                # Extract metadata. Pydantic doesn't like unions outside of Annotated
                if not (metadata := info.metadata):
                    try:
                        metadata = cast(Any, info.annotation).__args__[0].__metadata__
                    except AttributeError:
                        metadata = []
                if (meta := next((x for x in metadata if isinstance(x, Meta)), None)) is None:
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

                assert meta
                if target := getattr(meta, by_meta):
                    if include and not (target in include or name in include):
                        continue
                    if exclude and (target in exclude or name in exclude):
                        continue
                    assert target not in data, f"Duplicate key {target} from {obj} found in data"
                    # Handle Special Cases.
                    if hasattr(current, "get_secret_value"):
                        # If the field is a Secret[str], get the secret value
                        data[target] = current.get_secret_value()
                    else:
                        data[target] = current
        return data


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
    Secret[str],
    PlainSerializer(
        lambda v: cast(Secret[str], v).get_secret_value() if v else None, return_type=str | None, when_used="json"
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
    BeforeValidator(lambda v: v[0] if v and isinstance(v, Sequence) else v if isinstance(v, str) else None),
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
DslangCookieType: TypeAlias = Annotated[MorselModel, Meta(cookie=Cookies.DSLANG, config="client_settings.dslang")]
SiteCookieType: TypeAlias = Annotated[MorselModel, Meta(cookie=Cookies.SITE, config="client_settings.site")]
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


class ContextModel(BaseModel):
    def __init__(_model_self_, **data: Any) -> None:
        _model_self_.__pydantic_validator__.validate_python(
            data,
            self_instance=_model_self_,
            context=_init_context_var.get(),
        )


class LeafModel(EventedModel):
    def __init__(_model_self_, **data: Any) -> None:
        _model_self_.__pydantic_validator__.validate_python(
            data,
            self_instance=_model_self_,
            context=_init_context_var.get(),
        )
        Group = _model_self_.__signal_group__
        # the type error is "cannot assign to a class variable" ...
        # but if we don't use `ClassVar`, then the `dataclass_transform` decorator
        # will add _events: SignalGroup to the __init__ signature, for *all* user models
        _model_self_._events = Group(_model_self_)  # type: ignore [misc]

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

    def reset_field(self, field: str, value: Any = None):
        if field in self.model_fields:
            info = self.model_fields[field]
            value = value or info.get_default(call_default_factory=True)
            with self.events.blocked():
                # Set to default and remove from model_fields_set
                setattr(self, field, value)
                self.model_fields_set.remove(field)

    @overload
    @classmethod
    def model_fields_from_meta(cls, *, by_meta: MetaFields) -> Iterator[Tuple[str, str, FieldInfo]]: ...

    @overload
    @classmethod
    def model_fields_from_meta(
        cls, *, by_meta: Sequence[MetaFields]
    ) -> Iterator[Tuple[str, Sequence[str], FieldInfo]]: ...

    @classmethod
    def model_fields_from_meta(
        cls, *, by_meta: MetaFields | Sequence[MetaFields]
    ) -> Iterator[Tuple[str, str | Sequence[str], FieldInfo]]:
        by_meta = [by_meta] if isinstance(by_meta, str) else by_meta

        for field, info in cls.model_fields.items():
            assert isinstance(info, FieldInfo)
            if info.metadata:
                metadata = info.metadata
                assert isinstance(metadata, Collection)
            elif get_args(info.annotation) and issubclass(get_origin(get_args(info.annotation)[0]), Annotated):
                metadata = get_args(info.annotation)[0].__metadata__
            else:
                LOGGER.debug(f"Skipping {field} due to missing metadata")
                continue
            for meta in metadata:
                # Skip non meta instance in field Annotations
                if not isinstance(meta, Meta):
                    continue
                # Build value from required meta fields
                value = []
                for meta_field in by_meta:
                    if (v := getattr(meta, meta_field)) is not None:
                        value.append(v)
                # only yield if all required meta fields are present
                if len(value) != len(by_meta):
                    LOGGER.debug(f"Skipping {field} due to missing meta fields: {by_meta}")
                    continue
                yield field, value if len(value) > 1 else value[0], info

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

    @model_serializer(mode="wrap")
    def model_serialize(self, handler: Callable, info: SerializationInfo) -> dict[str, Any]:
        # Common case
        by_meta: MetaFields | None = None
        if isinstance(info.context, Mapping) and "by_meta" in info.context:
            by_meta = info.context["by_meta"]
        # Let default handler to serialize types. When done, fetch from that
        data = handler(self)
        if by_meta is None:
            return data
        # Serialize the model fields by meta if provided in context
        assert by_meta in get_args(MetaFields), f"Invalid by_meta: {by_meta}"
        for field, meta, field_info in self.model_fields_from_meta(by_meta=by_meta):
            value = data.pop(field)
            if field_info.exclude:
                continue
            if isinstance(info.exclude, Mapping | Sequence) and field in info.exclude:
                continue
            if isinstance(info.exclude, str) and field == info.exclude:
                continue
            if info.exclude_defaults and field not in self.model_fields_set:
                continue
            if info.exclude_none and value is None:
                continue
            # Split the field alias by '.' to create a nested dictionary
            keys = meta.split(".") if "." in meta else [meta]
            # Reverse the keys to create a nested dictionary
            for key in reversed(keys):
                value = {key: value}
            # Update the data dictionary with the nested dictionary
            data[key] = value[key]
        return data


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

            f_info = cast(BaseModel, model).model_fields[key]
            f_type = get_args(f_info.annotation) or (f_info.annotation,)
            f_type = f_type[0] if len(f_type) == 1 else None
            if f_type is not None and not isinstance(value, f_type):
                # try to cast the value to the field type
                if hasattr(value, "__cast__"):
                    value = value.__cast__(f_type)
                else:
                    raise ValueError(f"Invalid value type: {type(value)} for {name}, expected {f_type}")
                return
            setattr(model, key, value)

        # Recursively set the attribute
        deep_setattr(self, name, value, self.__class__.separator)
