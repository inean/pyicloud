from __future__ import annotations

from typing import Annotated

from pydantic import Field

from pyicloud.constants import Endpoints
from pyicloud.models.bodies import BodyModel, DynamicBodyModel
from pyicloud.models.cookies import CookiesModel
from pyicloud.models.fields import (
    AcceptType,
    AppleIdType,
    ContentTypeType,
    DslangCookieType,
    OriginType,
    PasswordType,
    ScntType,
    ServiceType,
    SessionIdType,
    SessionTokenType,
    SiteCookieType,
    TrustTokenType,
    XAppleDsWebSessionTokenType,
    XAppleWebauthHsaTrustType,
    XAppleWebauthTokenType,
    XAppleWebauthUserType,
    XAppleWebauthValidateType,
)
from pyicloud.models.headers import HeadersModel, OAuthHeadersModel
from pyicloud.sessions import (
    BaseRequest,
    BaseResponse,
    OAuthTransport,
    StaticEndpoint,
    serialize,
)


##
# Request
##
class AccountLoginEndpoint(StaticEndpoint):
    endpoint = Endpoints.ACCOUNT_LOGIN
    verb = "POST"
    content_type = "application/json"


class AccountLoginRequestHeaders(OAuthHeadersModel):
    accept: AcceptType = "application/json"
    origin: OriginType = Endpoints.HOME
    content_type: ContentTypeType = "application/json"

    # Required Headers
    scnt: ScntType
    session_id: SessionIdType


class AccountLoginServiceRequestHeaders(OAuthHeadersModel):
    accept: AcceptType = "application/json"
    origin: OriginType = Endpoints.HOME
    content_type: ContentTypeType = "application/json"


class AccountLoginRequestCookies(CookiesModel):
    dslang: DslangCookieType
    site: SiteCookieType


class AccountLoginRequestBody(BodyModel):
    ds_web_auth_token: SessionTokenType
    extended_login: Annotated[bool, Field(default=True)]
    trust_token: TrustTokenType | None = Field(default=None)


class AccountLoginServiceRequestBody(BodyModel):
    apple_id: AppleIdType
    password: PasswordType
    service: ServiceType


# For Two factor, token based Authentication
class AccountLoginRequest(
    BaseRequest[AccountLoginRequestHeaders, AccountLoginRequestCookies, AccountLoginRequestBody, AccountLoginEndpoint]
):
    pass


# For One factor Authentication
class AccountLoginServiceRequest(
    BaseRequest[
        AccountLoginServiceRequestHeaders,
        AccountLoginRequestCookies,
        AccountLoginServiceRequestBody,
        AccountLoginEndpoint,
    ]
):
    pass


##
# Response
##
class AccountLoginResponseHeaders(HeadersModel): ...


class AccountLoginResponseCookies(CookiesModel):
    webauth_hsa_trust: XAppleWebauthHsaTrustType | None = None
    webauth_user: XAppleWebauthUserType | None = None
    webauth_token: XAppleWebauthTokenType | None = None
    webauth_validate: XAppleWebauthValidateType | None = None
    ds_web_session_token: XAppleDsWebSessionTokenType | None = None


class AccountLoginResponseBody(DynamicBodyModel): ...


class AccountLoginResponse(
    BaseResponse[AccountLoginResponseHeaders, AccountLoginResponseCookies, AccountLoginResponseBody]
):
    pass


##
# Transport
##
@serialize
class AccountLogin(OAuthTransport[AccountLoginRequest | AccountLoginServiceRequest, AccountLoginResponse]):
    pass
