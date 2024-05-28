from __future__ import annotations  # noqa: I001

from abc import ABC
from typing import (
    Any,
    Protocol,
    Sequence,
    Callable,
    Self,
)
from pydantic import (
    BaseModel,
    RootModel,
    model_validator,
    model_serializer,
    ValidationInfo,
)
from pyicloud.models.morsel import MorselModel, JarTypes, JarTuple
from pyicloud.models.settings import Settings
from pyicloud.models.types import Meta, LeafModel


class ResponseModel(Protocol):
    cookies: BaseModel
    headers: BaseModel


class Cookies(RootModel):
    root: dict[str, Any]

    def __iter__(self):
        return iter(self.root)

    def __getitem__(self, name: str) -> dict:
        return self.root[name].model_dump()

    def __setitem__(self, name: str, value: dict | MorselModel | str):
        cookie = value
        if isinstance(value, str):
            cookie = MorselModel(name=name, value=value)
        if isinstance(value, dict):
            cookie = MorselModel.model_validate(value)
        assert isinstance(cookie, MorselModel), f"Invalid value type: {type(value)}"
        assert name == cookie.key, f"Invalid cookie key: {cookie.key}, expected: {name}"
        self.root[cookie.key] = cookie

    def __contains__(self, name: str):
        try:
            self.__getitem__(name)
            return True
        except KeyError:
            return False

    def __delitem__(self, name: str):
        del self.root[name]

    def __len__(self):
        return len(self.root)

    _NO_POP = object()

    def pop(self, key: str, default: Any = _NO_POP, /):
        try:
            return self.root.pop(key)
        except KeyError as err:
            if default != self._NO_POP:
                return default
            raise err

    def model_validate_from_response(self, response: ResponseModel, *, include=None, exclude=None):
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
            assert isinstance(value, MorselModel), f"Invalid value type: {config_key}, {type(value)}"
            self.root[config_key] = value

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
            return result
        if isinstance(data, dict):
            result = {}
            for key, value in data.items():
                cookie = MorselModel.model_validate(value) if isinstance(value, dict) else value
                assert isinstance(cookie, MorselModel), f"Invalid value type: {type(value)}"
                if key != cookie.key:
                    raise ValueError(f"Invalid cookie key: {cookie.key}, expected: {key}")
                result[key] = cookie
            return result
        raise AssertionError(f"Ivalid data type: {type(data)}")

    @model_serializer(mode="wrap")
    def model_dump_as_dict(self, handler, info) -> dict[str, Any]:
        data = handler(self)
        if info.mode == "python":
            return_data = {}
            for name, cookie in data.items():
                cookie_name, cookie_value = cookie.get("name") or cookie.get("key"), cookie["value"]
                assert name == cookie_name, f"Invalid cookie key: {cookie_name}, expected: {name}"
                return_data[cookie_name] = cookie_value
            data = return_data
        return data


class CookiesModel(LeafModel, ABC):
    @model_validator(mode="wrap")
    @classmethod
    def validate_from_jar(cls, data: dict[str, Any] | Self, handler: Callable, info: ValidationInfo) -> Self:
        cookies: JarTypes | Cookies | None = None

        if isinstance(data, cls):
            return handler(data)

        assert isinstance(data, dict), f"Invalid data type for '{cls}': {type(data)}"

        # Accept simple key/value pairs for cookies. Convert them to MorselModel
        for key, value in data.items():
            if isinstance(value, str):
                data[key] = MorselModel(name=key, value=value)
            elif isinstance(value, dict):
                data[key] = MorselModel.model_validate(value)

        # Try to fetch cookies from context
        if isinstance(info.context, dict):
            # If valid cookies are already set and missing from inpuyt data override them
            cookies = info.context.get("cookies", None)
            if isinstance(cookies, JarTuple) or isinstance(cookies, Cookies):
                cookies = Cookies.model_validate(cookies)
            if isinstance(cookies, Cookies):
                for field, meta_cookie, _ in cls.model_fields_from_meta(by_meta="cookie"):
                    if meta_cookie in cookies:
                        data.setdefault(field, cookies.pop(meta_cookie))

            # Try to set safe defaults from settings if not set previously
            settings = info.context.get("settings", None)
            if isinstance(settings, Settings):
                for field, meta_config, finfo in cls.model_fields_from_meta(by_meta="config"):
                    if meta_config in settings:
                        assert isinstance(finfo.annotation, type) and issubclass(finfo.annotation, MorselModel)
                        data.setdefault(field, MorselModel(name=field, value=settings[meta_config]))

        return handler(data)
