from __future__ import annotations

import datetime
import re
from http.cookiejar import Cookie, CookieJar
from http.cookies import BaseCookie, Morsel, _quote
from time import time
from typing import Any, Sequence, TypeAlias, cast

from httpx import Cookies
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

JarTypes: TypeAlias = dict[str, Morsel] | Cookies | CookieJar | Sequence
JarTuple = (dict, Cookies, CookieJar, Sequence)
# Extend Morsel reserved keywords to support missing attributes:
cast(dict, Morsel._reserved).update(  # type: ignore
    path_spec="path_spec",
    discard="discard",
    version="version",
    domain_dot="domain_dot",
)
cast(set, Morsel._flags).update(["path_spec", "discard", "domain_dot"])  # type: ignore


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
        if isinstance(jar, Cookies):
            jar = jar.jar
        if isinstance(jar, CookieJar):
            if cookie := next(filter(lambda c: c.name == cookie_name, jar), None):
                return cls.model_validate(cookie)
