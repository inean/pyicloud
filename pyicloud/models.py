from abc import ABC
from typing import Annotated, ClassVar

from pydantic import (
    SecretStr,
    BaseModel,
)
from pydantic import (
    computed_field,
    field_serializer,
    field_validator,
    Field,
)

import re
import uuid


class Tokens(BaseModel):
    session: Annotated[str | None, {"header": "X-Apple-Session-Token"}] = Field(
        None,
        serialization_alias="sessionToken",
    )
    trust: Annotated[str | None, {"header": "X-Apple-TwoSV-Trust-Token"}] = Field(
        None,
        serialization_alias="trustToken",
    )


class ClientSettings(BaseModel):
    language: str = Field("en-us")
    timezone: str = Field("US/Pacific")
    time_offset: str = Field(
        "GMT+02:00",
        serialization_alias="timeOffset",
    )
    client_id: str = Field(
        default_factory=lambda: f"auth-{str(uuid.uuid1()).lower()}",
        serialization_alias="client_settings.client_id",
    )

    @computed_field
    def locale(self) -> str:
        return str.upper(self.language.replace("-", "_"))


class AppleID(BaseModel):
    username: str = Field("", alias="apple_id", serialization_alias="username")
    password: SecretStr = Field(SecretStr(""))
    country_code: Annotated[str | None, {"header": "X-Apple-ID-Account-Country"}] = Field(
        None, serialization_alias="countryCode"
    )
    session_id: Annotated[str | None, {"header": "X-Apple-Session-ID"}] = Field(
        None,
        serialization_alias="sessionId",
    )
    with_family: bool = Field(
        True,
        serialization_alias="account.with_family",
    )

    @field_validator("username")
    def username_must_be_email(cls, v):
        print(f"Validating username {v}")
        # Apple ID must be a valid email or an empty string
        if v and not re.match(r"[^@]+@[^@]+\.[^@]+", v):
            raise ValueError("username must be a valid email")
        return v

    @field_serializer("password", when_used="json")
    def dump_secret(self, v: SecretStr):
        return v.get_secret_value()


class NestedModel(BaseModel, ABC):
    separator: ClassVar[str] = "."

    def __getitem__(self, key):
        def deep_getattr(model, key, sep="."):
            if sep in key:
                key, child_key = key.split(sep, 1)
                return deep_getattr(getattr(model, key), child_key, sep)
            return getattr(model, key)

        # Recursively get the attribute
        return deep_getattr(self, key, self.__class__.separator)

    def __setitem__(self, key, value):
        def deep_setattr(model, key, value, sep="."):
            if sep in key:
                key, child_key = key.split(sep, 1)
                deep_setattr(getattr(model, key), child_key, value, sep)
                return
            setattr(model, key, value)

        # Recursively set the attribute
        deep_setattr(self, key, value, self.__class__.separator)


class ConfigModel(NestedModel, revalidate_instances="always"):
    account: AppleID = Field(AppleID(), serialization_alias="account")
    tokens: Tokens = Field(Tokens(), serialization_alias="session")
    client_settings: ClientSettings = Field(ClientSettings(), serialization_alias="client_settings")
