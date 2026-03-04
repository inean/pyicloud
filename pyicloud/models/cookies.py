from __future__ import annotations  # noqa: I001

import re

from abc import ABC
from collections.abc import Iterator

from typing import (
    Annotated,
    Any,
    Callable,
    Protocol,
    Self,
    Sequence,
    get_args,
    get_origin,
)

from pydantic import (
    BaseModel,
    RootModel,
    ValidationError,
    ValidationInfo,
    model_serializer,
    model_validator,
)


from pyicloud.log import LOGGER
from pyicloud.models import LeafModel, Meta
from pyicloud.models.fields import JarTuple, JarTypes, MorselModel
from pyicloud.models.settings import Settings


class ResponseModel(Protocol):
    cookies: BaseModel
    headers: BaseModel


class Cookies(RootModel):
    root: dict[str, MorselModel]

    def __iter__(self) -> Iterator[MorselModel]:
        return iter(self.root.values())

    def __getitem__(self, name: str) -> MorselModel:
        # Suggar case. constant
        if name in self.root:
            return self.root[name]
        # Try constants but with morsel keys
        for cookie in self.root.values():
            if name == cookie.key:
                return cookie
        # Try to match name as a pattern
        try:
            pattern = re.compile(name)
            for candidate, cookie in self.root.items():
                if pattern.match(candidate):
                    return cookie
        except re.error:
            pass

        raise KeyError(name)

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
            for cookie_name in data:
                cookie = MorselModel.model_validate(cookie_name)
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
                if isinstance(value, dict):
                    value = MorselModel.model_validate(value)
                if not isinstance(value, MorselModel):
                    raise ValueError(f"Invalid value type: {type(value)}")
                # Common case. key is the same as cookie key
                if key == value.key or re.match(key, value.key):
                    result[key] = value
                    continue
                # This shouldn't be reached...
                raise ValueError(f"Invalid cookie key: {value.key}, expected: {key}")
            return result
        # Invalid data type
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
        fields: dict[str, str | re.Pattern] = {}
        cookies: JarTypes | Cookies | None = None

        if isinstance(data, cls):
            return handler(data)

        assert isinstance(data, dict), f"Invalid data type for '{cls}': {type(data)}"

        # Accept simple key/value pairs for cookies. Convert them to MorselModel
        for name, value in data.copy().items():
            if isinstance(value, str):
                data[name] = MorselModel(name=name, value=value)
                continue
            if isinstance(value, dict):
                # Convert to MorselModel
                data[name] = MorselModel.model_validate(data.pop(name))
            # Ensure MosrselModel keys are used as dict keys
            if isinstance(value, MorselModel):
                data[value.key] = data.pop(name)
                continue
            # Only Morsel compatible types are allowed
            raise ValidationError(f"Invalid value type: {type(value)}")

        # Try to fetch cookies from context
        if isinstance(info.context, dict):
            # If valid cookies are already set and missing from inpuyt data override them
            cookies = info.context.get("cookies", None)
            # A string is also a valid sequence...
            if isinstance(cookies, JarTuple) or isinstance(cookies, Cookies):
                cookies = Cookies.model_validate(cookies)
                assert isinstance(cookies, Cookies)
            if isinstance(cookies, Cookies):
                for cookie in cookies:
                    assert isinstance(cookie, MorselModel)
                    data.setdefault(cookie.key, cookie)

        # Inspect model fields
        for field, cookie, _ in cls.model_fields_from_meta(by_meta="cookie"):
            fields[field] = cookie
        # Inspect field annotations
        for field, annotation in cls.__annotations__.items():
            # skip field if ir's a model field
            if field in cls.model_fields:
                continue
            if get_origin(annotation) is Annotated:
                for meta in get_args(annotation)[1:]:
                    if not isinstance(meta, Meta):
                        continue
                    if meta.cookie is None:
                        continue
                    fields[field] = meta.cookie
        # Parse fields
        for field, cookie_name in fields.items():
            # Simple case: field and cookie_name are the same
            if field == cookie_name:
                continue
            # Simple case if cookie_name is a constant string
            if cookie_name in data:
                # Purge cookie
                assert field not in data
                data[field] = data.pop(cookie_name)
                continue
            # Try to match cookie_name as a pattern
            try:
                cookie_pattern = re.compile(cookie_name)
            except re.error:
                LOGGER.debug(f"Invalid cookie pattern: {cookie_name}")
                continue
            for key in data.keys():
                if cookie_pattern.match(key):
                    assert field not in data
                    data[field] = data.pop(key)
                    break
            else:
                LOGGER.debug(f"Cookie not found: '{cookie_name}'")

        # Try to set safe defaults from settings if not set previously
        if isinstance(info.context, dict):
            settings = info.context.get("settings", None)
            if isinstance(settings, Settings):
                for field, (cookie, config), finfo in cls.model_fields_from_meta(by_meta=["cookie", "config"]):
                    if config in settings:
                        value = settings[config]
                        assert isinstance(value, str)
                        assert isinstance(finfo.annotation, type) and issubclass(finfo.annotation, MorselModel)
                        data.setdefault(field, MorselModel(name=cookie, value=value))

        return handler(data)
