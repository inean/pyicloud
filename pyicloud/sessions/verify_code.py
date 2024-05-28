from __future__ import annotations  # noqa: I001

from typing import Type, Annotated, Self, override, Any

from pyicloud.constants import Endpoints
from pyicloud.models.body import BodyModel

from pyicloud.models.cookies import CookiesModel
from pyicloud.models.headers import HeadersModel
from pydantic import BaseModel, ConfigDict, Field, field_validator

from pyicloud.models.types import (
    AaspType,
    Acn01Type,
    CountryCodeType,
    DslangCookieType,
    ScntType,
    SessionIdType,
    SessionTokenType,
    SiteCookieType,
    TrustTokenEligibleType,
    TrustTokenType,
    XAppleDsWebSessionTokenType,
    XAppleUniqueClientIdType,
    XAppleWebauthHsaLoginType,
    XAppleWebauthLoginType,
    XAppleWebauthUserType,
    XAppleWebauthValidateType,
)
from pyicloud.sessions.base import BaseRequest, BaseResponse, Endpoint, OAuthTransport, RequestConfig, ResponseConfig
from pyicloud.sessions.decorators import serialize


class LoggedRequestHeaders(HeadersModel):
    # Header Fields
    scnt: ScntType
    session_id: SessionIdType


class LoggedRequestCookies(CookiesModel):
    # Cookie Fields
    dslang: DslangCookieType
    site: SiteCookieType
    acn01: Acn01Type
    aasp: AaspType

    client_id: XAppleUniqueClientIdType
    webauth_login: XAppleWebauthLoginType
    webauth_user: XAppleWebauthUserType
    webauth_validate: XAppleWebauthValidateType
    webauth_hsa_login: XAppleWebauthHsaLoginType
    session_token: XAppleDsWebSessionTokenType


class LoggedRequestBody(BodyModel):
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


class LoggedRequestEndpoint(Endpoint):
    url = Endpoints.VERIFY
    verb = "POST"
    content_type = "application/json"


class LoggedRequest(BaseRequest):
    _config = RequestConfig(
        headers=LoggedRequestHeaders,
        cookies=LoggedRequestCookies,
        body=LoggedRequestBody,
        endpoint=LoggedRequestEndpoint,
    )


class LoggedResponseHeaders(HeadersModel):
    country_code: CountryCodeType | None = None
    trust_token: TrustTokenType | None = None
    turst_token_eligible: TrustTokenEligibleType | None = None
    session_token: SessionTokenType | None = None
    session_id: SessionIdType | None = None
    scnt: ScntType | None = None


class LoggedResponseCookies(CookiesModel):
    dslang: DslangCookieType
    site: SiteCookieType
    acn01: Acn01Type | None = None  # On login error, the acn01 cookie is not returned
    aasp: AaspType

    client_id: XAppleUniqueClientIdType
    webauth_login: XAppleWebauthLoginType
    webauth_user: XAppleWebauthUserType
    webauth_validate: XAppleWebauthValidateType
    # webauth_hsa_login: XAppleWebauthHsaLoginType
    session_token: XAppleDsWebSessionTokenType


class LoggedResponse(BaseResponse):
    _config = ResponseConfig(
        headers=LoggedResponseHeaders,
        cookies=LoggedResponseCookies,
    )

    def __bool__(self):
        """Return True if the response is successful."""
        # if a 409 is returned, the user login was successfull but a 2FA is needed
        return True if self.status_code == 409 else super().__bool__()


@serialize
class VerifyHSA2Code(OAuthTransport[LoggedRequest, LoggedResponse]):
    @property
    def response_cls(self) -> Type[LoggedResponse]:
        return LoggedResponse

    @property
    def request_cls(self) -> Type[LoggedRequest]:
        return LoggedRequest

    @override
    def dump_content(self) -> dict[str, Any]:
        return self.request.body.json_data
