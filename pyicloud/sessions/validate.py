from __future__ import annotations

from typing import Type

from pyicloud.constants import Endpoints
from pyicloud.models.bodies import NullModel
from pyicloud.models.fields import (
    AcceptType,
    ContentTypeType,
    DslangCookieType,
    OriginType,
    SiteCookieType,
)
from pyicloud.models.headers import HeadersModel
from pyicloud.sessions import (
    BaseRequest,
    BaseResponse,
    Endpoint,
    OAuthTransport,
    RequestConfig,
    ResponseConfig,
    serialize,
)
from pyicloud.sessions.session import SessionBody, SessionCookies, SessionHeaders


##
# Request
##
class ValidateEndpoint(Endpoint):
    url = Endpoints.VALIDATE
    verb = "POST"
    content_type = "application/json"


class ValidateRequestHeaders(SessionHeaders):
    accept: AcceptType = "application/json"
    origin: OriginType = Endpoints.HOME
    content_type: ContentTypeType = "application/json"


class ValidateRequestCookies(SessionCookies):
    dslang: DslangCookieType
    site: SiteCookieType


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


class ValidateResponseCookies(SessionCookies): ...


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
