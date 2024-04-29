from __future__ import annotations  # noqa: I001

import locale
import re
import bisect
from typing import Any, cast, Protocol, Sequence, override, get_origin

from pydantic import (
    BaseModel,
    ConfigDict,
    RootModel,
    model_validator,
    model_serializer,
)
from pyicloud.constants import ISO_3166_1_CODES_3
from pyicloud.models.morsel import MorselModel, JarTypes

from pyicloud.models.types import (
    LeafModel,
    InitAbstractModel,
    Meta,
)


class AbstractCookiesJar:
    @model_validator(mode="before")
    @classmethod
    def model_validate_jartypes(cls, data: JarTypes) -> dict[str, Any]:
        if isinstance(data, Sequence):
            result = {}
            for cookie_value in data:
                cookie = MorselModel.model_validate(cookie_value)
                result[cookie.key] = cookie
            return result
        if hasattr(data, "jar") or hasattr(data, "extract_cookies"):  # httpx.Cookies or CookieJar
            result = {}
            for cookie in data:
                # Extract Cookie information and store it in a MorselCookie model
                cookie_name = cookie if isinstance(cookie, str) else cookie.name
                if morsel_cookie := MorselModel.from_jar(cookie_name=str(cookie_name), jar=data):
                    result[cookie_name] = morsel_cookie
            data = result

        assert isinstance(data, dict), f"Invalid data type: {type(data)}"
        for key, value in data.items():
            cookie = cast(MorselModel, value)
            if key != cookie.key:
                raise ValueError(f"Invalid cookie key: {cookie.key}, expected: {key}")
        return data

    @model_serializer(mode="wrap")
    def model_dump_as_dict(self, handler, info) -> dict[str, str]:
        data = handler(self)
        if info.mode == "python":
            data = {cookie["key"]: cookie["value"] for cookie in data.values()}
        return data


class CookiesModel(LeafModel, AbstractCookiesJar):
    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="before")
    @classmethod
    @override
    def model_validate_jartypes(cls, data: JarTypes) -> dict[str, Any]:
        data, cookies = {}, super().model_validate_jartypes(data)  # type: ignore
        # Parse Cooies dict. Try to math available cookies to the ones in fields and return data
        for field, info in cls.model_fields.items():
            if not (metadata := info.metadata):
                try:
                    metadata = cast(Any, info.annotation).__args__[0].__metadata__
                except AttributeError:
                    metadata = []
            # Get header metadata entry from field info. If exists, check if it is
            # in data and update data with alias and value
            if meta := next((x for x in metadata if isinstance(x, Meta)), None):
                if cookie := cast(dict, cookies).get(meta.cookie, None):
                    data[field] = cookie
        return data


class InitCookiesModel(InitAbstractModel, CookiesModel):
    @classmethod
    def dslang_default(cls):
        locale_code = locale.getlocale()[0] or "US-EN"
        return MorselModel(name="dslang", value=locale_code.upper())

    @classmethod
    def site_default(cls):
        locale_code = locale.getlocale()[0] or "EN-US"
        alpha3166_1 = re.split("-|_", locale_code)[0].upper()
        alpha3166_3 = bisect.bisect_left(ISO_3166_1_CODES_3, alpha3166_1)
        return MorselModel(name="site", value=ISO_3166_1_CODES_3[alpha3166_3])


# class SigInCookiesModel(LoginCookiesModel):
#    acn01: Acn01Type


# class WebAuthCookiesModel(SigInCookiesModel):
#     x_apple_ds_web_session_token: XAppleDsWebSessionTokenType
#     x_apple_unique_client_id: XAppleUniqueClientIdType
#     x_apple_webauth_login: XAppleWebauthLoginType
#     x_apple_webauth_user: XAppleWebauthUserType
#     x_apple_webauth_validate: XAppleWebauthValidateType


# class WebAuthHsaCookiesModel(LoginCookiesModel):
#     x_apple_webauth_hsa_login: XAppleWebauthHsaLoginType


# class WebAuthFmipCookiesModel(WebAuthCookiesModel):
#     x_apple_webauth_fmip: XAppleWebauthFmipType
#     x_apple_webauth_hsa_trust: XAppleWebauthHsaTrustType
#     x_apple_webauth_token: XAppleWebauthTokenType


class ResponseModel(Protocol):
    cookies: BaseModel
    headers: BaseModel


class Cookies(RootModel[dict[str, MorselModel]], AbstractCookiesJar):
    model_config = ConfigDict(frozen=True)

    root: dict[str, MorselModel] = {}

    @model_validator(mode="before")
    def init_model(cls, value: dict[str, MorselModel]) -> dict[str, MorselModel]:
        info = cls.model_fields["root"]
        if info.annotation and isinstance(value, get_origin(info.annotation)):
            return value
        # We are breaking the rules here, becouse pydantic will interpret that returned
        # value was set by user and not by default, but default loginc seems to not work
        # with RootModels
        return info.get_default(call_default_factory=True)

    def __iter__(self):
        return iter(self.root)

    def __getitem__(self, name: str) -> dict:
        return self.root[name].model_dump()

    def __setitem__(self, name: str, value: dict):
        self.root[name] = MorselModel.model_validate(value)

    def __contains__(self, name: str):
        try:
            self.__getitem__(name)
            return True
        except AttributeError:
            return False

    def __delitem__(self, name: str):
        raise NotImplementedError

    def model_update(self, response: ResponseModel, *, include=None, exclude=None):
        """Create a response from a httpx response."""
        cookies = Meta.model_dump_meta(
            response,
            by_meta="cookie",
            include=include,
            exclude=exclude,
            exclude_unset=True,
            exclude_defaults=True,
        )
        # Update settings with values from response
        for config_key, value in cookies.items():
            self[config_key] = value
