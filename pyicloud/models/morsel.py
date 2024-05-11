from __future__ import annotations

from http.cookiejar import Cookie, CookieJar
from http.cookies import BaseCookie, Morsel, _quote
from time import time
from typing import Any, Sequence, cast

from httpx import Cookies
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    model_validator,
)

type JarTypes = dict[str, Morsel[str]] | Cookies | CookieJar | Sequence

# Extend Morsel redserved keywords to support missing attributes:
# path_spec

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
    path: str | None = None
    comment: str | None = None
    domain: str | None = None
    max_age: float | None = Field(default=None, alias="max-age")
    secure: bool | None = None
    httponly: bool | None = None
    domain_dot_: bool | None = None
    discard: bool | None = None
    path_spec: bool | None = None
    samesite: str | None = None
    version: int | None = None

    @model_validator(mode="before")
    def extract_from_morsel_or_cookie(cls, data: Cookie | Morsel | str | dict[str, Any]) -> Any:
        cookie = data
        if isinstance(data, str):
            jar = BaseCookie()
            jar.load(data)
            assert len(jar) == 1, f"Invalid cookie string: {data}"
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

    def model_dump_str(self, attrs=None, header="Set-Cookie:") -> str:
        morsel, values = Morsel(), self.model_dump()
        morsel.set(values.pop("key"), values.pop("value"), _quote(self.value))
        morsel.update(values)
        return morsel.output(attrs, header)

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
