from __future__ import annotations  # noqa: I001

from collections.abc import Sequence
from typing import Type, Annotated, Self, override, Any

from pyicloud.constants import Endpoints
from pyicloud.models.body import BodyModel, EmptyModel

from pyicloud.models.cookies import CookiesModel
from pyicloud.models.headers import HeadersModel
from pydantic import BaseModel, ConfigDict, Field, field_validator

from pyicloud.models.types import (
    AaspType,
    Acn01Type,
    AuthAttributesType,
    CountryCodeType,
    DslangCookieType,
    OAuthGrantCodeType,
    RequestIdType,
    ScntType,
    SessionIdType,
    SessionTokenType,
    SiteCookieType,
)
from pyicloud.sessions.base import (
    BaseRequest,
    BaseResponse,
    Endpoint,
    OAuthTransport,
    RequestConfig,
    ResponseConfig,
)
from pyicloud.sessions.decorators import serialize
from pyicloud.sessions.signin import SignInRequestHeaders


##
# Request
##
class SecurityCodeRequestEndpoint(Endpoint):
    url = Endpoints.SECURITY_CODE
    verb = "POST"
    content_type = "application/json"


class SecurityCodeRequestHeaders(SignInRequestHeaders):
    # Header Fields
    scnt: ScntType
    session_id: SessionIdType


class SecurityCodeRequestCookies(CookiesModel):
    # Cookie Fields
    dslang: DslangCookieType
    site: SiteCookieType
    acn01: Acn01Type
    aasp: AaspType


class SecurityCodeRequestBody(BodyModel):
    model_config = ConfigDict(populate_by_name=True)

    class Code(BaseModel):
        code: Annotated[str, Field(pattern=r"^\d{6}$")]

        def __eq__(self, other: Self | str) -> bool:
            if isinstance(other, str):
                return self.code == other
            return super().__eq__(other)

        def __str__(self) -> str:
            return self.code

    # Body fields
    security_code: Code = Field(..., alias="securityCode")

    @field_validator("security_code", mode="before")
    @classmethod
    def validate_security_code(cls, value: Code | str) -> Code:
        return cls.Code(code=value) if isinstance(value, str) else value


class SecurityCodeRequest(
    BaseRequest[
        SecurityCodeRequestHeaders,
        SecurityCodeRequestCookies,
        SecurityCodeRequestBody,
        SecurityCodeRequestEndpoint,
    ]
):
    _config = RequestConfig(
        headers=SecurityCodeRequestHeaders,
        cookies=SecurityCodeRequestCookies,
        body=SecurityCodeRequestBody,
        endpoint=SecurityCodeRequestEndpoint,
    )


##
# Response
##
class SecurityCodeResponseHeaders(HeadersModel):
    request_id: RequestIdType
    scnt: ScntType
    session_id: SessionIdType | None = None
    oauth_grant_code: OAuthGrantCodeType | None = None
    auth_attributes: AuthAttributesType | None = None
    country_code: CountryCodeType | None = None
    session_token: SessionTokenType | None = None


class SecurityCodeResponseCookies(CookiesModel):
    dslang: DslangCookieType
    site: SiteCookieType


class SecurityCodeResponseBody(EmptyModel): ...


class SecurityCodeResponse(
    BaseResponse[
        SecurityCodeResponseHeaders,
        SecurityCodeResponseCookies,
        SecurityCodeResponseBody,
    ]
):
    _config = ResponseConfig(
        headers=SecurityCodeResponseHeaders,
        cookies=SecurityCodeResponseCookies,
        body=SecurityCodeResponseBody,
    )

    def __bool__(self):
        """Return True if the response is successful."""
        return self.status_code == 204


##
# Transport
##
@serialize
class SecurityCode(OAuthTransport[SecurityCodeRequest, SecurityCodeResponse]):
    @override
    def dump_content(
        self,
        content: bytes | dict[str, Any] | None = None,
        *,
        include: Sequence[str] | None = None,
        exclude: Sequence[str] | None = None,
        exclude_unset=True,
        exclude_defaults=False,
        context: Any = None,
    ) -> bytes | dict[str, Any] | None:
        content = content or {}
        assert isinstance(content, dict), "Content must be a dictionary."
        content.update(self.request.body.json_data)
        return content

    @property
    def response_cls(self) -> Type[SecurityCodeResponse]:
        return SecurityCodeResponse

    @property
    def request_cls(self) -> Type[SecurityCodeRequest]:
        return SecurityCodeRequest
