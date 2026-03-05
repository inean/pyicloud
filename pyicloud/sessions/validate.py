from __future__ import annotations

from typing import Type

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
from pyicloud.sessions import (
    BaseRequest,
    BaseResponse,
    OAuthTransport,
    RequestConfig,
    ResponseConfig,
    StaticEndpoint,
    serialize,
)
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
    _config = RequestConfig(
        headers=ValidateRequestHeaders,
        cookies=ValidateRequestCookies,
        body=ValidateRequestBody,
        endpoint=ValidateEndpoint,
    )


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
    _config = ResponseConfig(
        headers=ValidateResponseHeaders,
        cookies=ValidateResponseCookies,
        body=ValidateResponseBody,
    )


##
# Transport
##
@serialize
class Validate(OAuthTransport[ValidateRequest, ValidateResponse]):
    @property
    def response_cls(self) -> Type[ValidateResponse]:
        return ValidateResponse

    @property
    def request_cls(self) -> Type[ValidateRequest]:
        return ValidateRequest
