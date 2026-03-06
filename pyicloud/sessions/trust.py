from __future__ import annotations

from pyicloud.constants import Endpoints
from pyicloud.models.bodies import EmptyModel
from pyicloud.models.cookies import CookiesModel
from pyicloud.models.fields import (
    AcceptType,
    Acn01Type,
    AuthAttributesType,
    CountryCodeType,
    DesType,
    DslangCookieType,
    OAuthGrantCodeType,
    OriginType,
    RequestIdType,
    ScntType,
    SessionIdType,
    SessionTokenType,
    SiteCookieType,
    TrustTokensType,
)
from pyicloud.models.headers import HeadersModel, OAuthHeadersModel
from pyicloud.sessions._contracts import BaseRequest, BaseResponse, StaticEndpoint
from pyicloud.sessions._serialize import serialize
from pyicloud.sessions._transport import OAuthTransport


##
# Request
##
class TrustEndpoint(StaticEndpoint):
    endpoint = Endpoints.TRUST
    verb = "GET"
    content_type = "application/json"

    # Query parameters


class TrustRequestHeaders(OAuthHeadersModel):
    accept: AcceptType = "application/json"
    origin: OriginType = Endpoints.HOME

    # Header Fields
    scnt: ScntType
    session_id: SessionIdType


class TrustRequestCookies(CookiesModel):
    dslang: DslangCookieType
    site: SiteCookieType
    # Cookie Fields
    acn01: Acn01Type


class TrustRequestBody(EmptyModel): ...


class TrustRequest(BaseRequest[TrustRequestHeaders, TrustRequestCookies, TrustRequestBody, TrustEndpoint]):
    pass


##
# Response
##
class TrustResponseHeaders(HeadersModel):
    # Required Headers
    request_id: RequestIdType
    scnt: ScntType
    # Required Headers only on successful response
    trust_token: TrustTokensType | None = None
    session_id: SessionIdType | None = None
    oauth_grant_code: OAuthGrantCodeType | None = None
    auth_attributes: AuthAttributesType | None = None
    country_code: CountryCodeType | None = None
    session_token: SessionTokenType | None = None


class TrustResponseCookies(CookiesModel):
    dslang: DslangCookieType
    site: SiteCookieType
    des: DesType | None = None


class TrustResponseBody(EmptyModel): ...


class TrustResponse(BaseResponse[TrustResponseHeaders, TrustResponseCookies, TrustResponseBody]):
    pass

    def __bool__(self):
        """Return True if the response is successful."""
        return self.status_code == 204


##
# Transport
##
@serialize
class Trust(OAuthTransport[TrustRequest, TrustResponse]):
    pass
