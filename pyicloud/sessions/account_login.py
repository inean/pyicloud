from __future__ import annotations

from typing import Annotated, Type

from pydantic import Field

from pyicloud.constants import Endpoints
from pyicloud.models.bodies import BodyModel, DynamicBodyModel
from pyicloud.models.cookies import CookiesModel
from pyicloud.models.fields import (
    AcceptType,
    AppleIdType,
    ContentTypeType,
    DesType,
    DslangCookieType,
    OriginType,
    PasswordType,
    PcsCloudkitType,
    PcsDocumentsType,
    PcsMailType,
    PcsNewsType,
    PcsNotesType,
    PcsPhotosType,
    PcsSafariType,
    PcsSharingType,
    ScntType,
    ServiceType,
    SessionIdType,
    SessionTokenType,
    SiteCookieType,
    TrustTokenType,
    XAppleClientIdType,
    XAppleDsWebSessionTokenType,
    XAppleWebauthHsaLoginType,
    XAppleWebauthHsaTrustType,
    XAppleWebauthLoginType,
    XAppleWebauthTokenType,
    XAppleWebauthUserType,
    XAppleWebauthValidateType,
    XAppleWebKBType,
)
from pyicloud.models.headers import HeadersModel, OAuthHeadersModel
from pyicloud.sessions import (
    BaseRequest,
    BaseResponse,
    Endpoint,
    OAuthTransport,
    RequestConfig,
    ResponseConfig,
    serialize,
)


##
# Request
##
class AccountLoginEndpoint(Endpoint):
    url = Endpoints.ACCOUNT_LOGIN
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
    des: DesType | None = None


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
    _config = RequestConfig(
        headers=AccountLoginRequestHeaders,
        cookies=AccountLoginRequestCookies,
        body=AccountLoginRequestBody,
        endpoint=AccountLoginEndpoint,
    )


# For One factor Authentication
class AccountLoginServiceRequest(
    BaseRequest[
        AccountLoginServiceRequestHeaders,
        AccountLoginRequestCookies,
        AccountLoginServiceRequestBody,
        AccountLoginEndpoint,
    ]
):
    _config = RequestConfig(
        headers=AccountLoginServiceRequestHeaders,
        cookies=AccountLoginRequestCookies,
        body=AccountLoginServiceRequestBody,
        endpoint=AccountLoginEndpoint,
    )


##
# Response
##
class AccountLoginResponseHeaders(HeadersModel): ...


class AccountLoginResponseCookies(CookiesModel):
    client_id: XAppleClientIdType | None = None
    # HomeKit?
    webauth_hsa_trust: XAppleWebauthHsaTrustType | None = None
    # webauth_hsa_login is emptied on successful login
    webauth_hsa_login: XAppleWebauthHsaLoginType | None = None

    # PCS Cookies
    Documents: PcsDocumentsType | None = None
    Photos: PcsPhotosType | None = None
    Cloudkit: PcsCloudkitType | None = None
    Safari: PcsSafariType | None = None
    Mail: PcsMailType | None = None
    Notes: PcsNotesType | None = None
    News: PcsNewsType | None = None
    Sharing: PcsSharingType | None = None

    # Web Auth
    webauth_login: XAppleWebauthLoginType | None = None
    webauth_user: XAppleWebauthUserType | None = None
    webauth_token: XAppleWebauthTokenType | None = None
    webauth_validate: XAppleWebauthValidateType | None = None

    # Kb dynamic cookie
    web_kb: XAppleWebKBType | None = None
    # Web Session
    ds_web_session_token: XAppleDsWebSessionTokenType | None = None


class AccountLoginResponseBody(DynamicBodyModel): ...


class AccountLoginResponse(
    BaseResponse[AccountLoginResponseHeaders, AccountLoginResponseCookies, AccountLoginResponseBody]
):
    _config = ResponseConfig(
        headers=AccountLoginResponseHeaders,
        cookies=AccountLoginResponseCookies,
        body=AccountLoginResponseBody,
    )


##
# Transport
##
@serialize
class AccountLogin(OAuthTransport[AccountLoginRequest | AccountLoginServiceRequest, AccountLoginResponse]):
    @property
    def response_cls(self) -> Type[AccountLoginResponse]:
        return AccountLoginResponse

    @property
    def request_cls(self) -> Type[AccountLoginRequest | AccountLoginServiceRequest]:
        return AccountLoginServiceRequest if "service" in self._data else AccountLoginRequest
