from __future__ import annotations  # noqa: I001

from typing import Annotated, Self

from pyicloud.constants import Endpoints
from pyicloud.models.bodies import BodyModel, EmptyModel

from pyicloud.models.cookies import CookiesModel
from pyicloud.models.headers import HeadersModel
from pydantic import BaseModel, ConfigDict, Field, field_validator

from pyicloud.models.fields import (
    AaspType,
    AcceptType,
    Acn01Type,
    AuthAttributesType,
    ContentTypeType,
    CountryCodeType,
    DslangCookieType,
    OAuthGrantCodeType,
    OriginType,
    RequestIdType,
    ScntType,
    SessionIdType,
    SessionTokenType,
    SiteCookieType,
)
from pyicloud.models.headers import OAuthHeadersModel
from pyicloud.sessions._contracts import BaseRequest, BaseResponse, StaticEndpoint
from pyicloud.sessions._serialize import serialize
from pyicloud.sessions._transport import OAuthTransport


##
# Request
##
class SecurityCodeRequestEndpoint(StaticEndpoint):
    endpoint = Endpoints.SECURITY_CODE
    verb = "POST"
    content_type = "application/json"


class SecurityCodeRequestHeaders(OAuthHeadersModel):
    accept: AcceptType = "application/json"
    origin: OriginType = Endpoints.HOME
    content_type: ContentTypeType = "application/json"

    # Header Fields
    scnt: ScntType
    session_id: SessionIdType


class SecurityCodeRequestCookies(CookiesModel):
    # Cookie Fields
    dslang: DslangCookieType
    site: SiteCookieType
    acn01: Acn01Type
    aasp: AaspType | None = None


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
    pass


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
    pass

    def __bool__(self):
        """Return True if the response is successful."""
        return self.status_code == 204


##
# Transport
##
@serialize
class SecurityCode(OAuthTransport[SecurityCodeRequest, SecurityCodeResponse]):
    pass
