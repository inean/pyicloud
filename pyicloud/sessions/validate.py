from __future__ import annotations

from pyicloud.constants import Endpoints
from pyicloud.models.bodies import NullModel
from pyicloud.models.cookies import CookiesModel
from pyicloud.models.fields import (
    ContentTypeType,
    DslangCookieType,
    SiteCookieType,
    XAppleDsWebSessionTokenType,
    XAppleWebauthHsaTrustType,
    XAppleWebauthTokenType,
    XAppleWebauthUserType,
    XAppleWebauthValidateType,
)
from pyicloud.models.headers import HeadersModel
from pyicloud.sessions._contracts import BaseRequest, BaseResponse, StaticEndpoint
from pyicloud.sessions._serialize import serialize
from pyicloud.sessions._transport import OAuthTransport
from pyicloud.sessions.session import SessionBody, SessionHeaders


##
# Request
##
class ValidateEndpoint(StaticEndpoint):
    endpoint = Endpoints.VALIDATE
    verb = "POST"
    content_type = "application/json"


class ValidateRequestHeaders(SessionHeaders):
    content_type: ContentTypeType = "application/json"


class ValidateRequestCookies(CookiesModel):
    dslang: DslangCookieType
    site: SiteCookieType
    webauth_hsa_trust: XAppleWebauthHsaTrustType | None = None
    webauth_user: XAppleWebauthUserType
    webauth_token: XAppleWebauthTokenType
    webauth_validate: XAppleWebauthValidateType
    ds_web_session_token: XAppleDsWebSessionTokenType


class ValidateRequestBody(NullModel): ...


# For Two factor, token based Authentication
class ValidateRequest(
    BaseRequest[ValidateRequestHeaders, ValidateRequestCookies, ValidateRequestBody, ValidateEndpoint]
):
    pass


##
# Response
##
class ValidateResponseHeaders(HeadersModel): ...


class ValidateResponseCookies(CookiesModel):
    webauth_token: XAppleWebauthTokenType | None = None
    webauth_validate: XAppleWebauthValidateType | None = None
    ds_web_session_token: XAppleDsWebSessionTokenType | None = None


class ValidateResponseBody(SessionBody): ...


class ValidateResponse(BaseResponse[ValidateResponseHeaders, ValidateResponseCookies, ValidateResponseBody]):
    pass


##
# Transport
##
@serialize
class Validate(OAuthTransport[ValidateRequest, ValidateResponse]):
    pass
