from __future__ import annotations

from typing import Any, Protocol, TypeVar

from httpx import AsyncClient

from pyicloud.constants import Endpoints
from pyicloud.models.bodies import BodyModel, DynamicBodyModel, EmptyModel
from pyicloud.models.cookies import CookiesModel
from pyicloud.models.fields import (
    AcceptType,
    DslangCookieType,
    OriginType,
    ScntType,
    SessionIdType,
    SiteCookieType,
    XAppleClientIdType,
    XAppleDsWebSessionTokenType,
    XAppleWebauthHsaTrustType,
    XAppleWebauthLoginType,
    XAppleWebauthTokenType,
    XAppleWebauthUserType,
    XAppleWebauthValidateType,
    XAppleWebKBType,
)
from pyicloud.models.headers import HeadersModel, OAuthHeadersModel
from pyicloud.sessions._contracts import BaseRequest, BaseResponse, DynamicEndpoint, RequestConfig, ResponseConfig
from pyicloud.sessions._serialize import serialize
from pyicloud.sessions._transport import OAuthTransport


class SessionHeaders(OAuthHeadersModel):
    # Constant Headers
    origin: OriginType = Endpoints.HOME
    accept: AcceptType = "application/json"

    # Required Headers
    scnt: ScntType
    session_id: SessionIdType


class SessionCookies(CookiesModel):
    dslang: DslangCookieType
    site: SiteCookieType
    client_id: XAppleClientIdType | None = None
    webauth_hsa_trust: XAppleWebauthHsaTrustType | None = None
    webauth_login: XAppleWebauthLoginType | None = None
    webauth_user: XAppleWebauthUserType | None = None
    webauth_token: XAppleWebauthTokenType
    webauth_validate: XAppleWebauthValidateType
    web_kb: XAppleWebKBType | None = None
    ds_web_session_token: XAppleDsWebSessionTokenType


class SessionBody(DynamicBodyModel): ...


BodyRq = TypeVar("BodyRq", bound=BodyModel)
BodyRs = TypeVar("BodyRs", bound=BodyModel)
E = TypeVar("E", bound=DynamicEndpoint)


##
# Request
##
class SessionRequest(BaseRequest[SessionHeaders, SessionCookies, BodyRq, E]):
    _config = RequestConfig(headers=SessionHeaders, cookies=SessionCookies)


##
# Response
##
class SessionResponse(BaseResponse[HeadersModel, SessionCookies, BodyRs]):
    _config = ResponseConfig(headers=HeadersModel, cookies=SessionCookies)


##
# Transport
##
Rq = TypeVar("Rq", bound=SessionRequest)
Rs = TypeVar("Rs", bound=SessionResponse)


class Session(OAuthTransport[Rq, Rs]):
    class Application(Protocol):
        settings: Any
        cookies: Any

    def __init__(
        self,
        application: Application,
        *,
        client: AsyncClient | None = None,
        data: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            settings=application.settings,
            cookies=application.cookies,
            client=client,
            data=data,
        )


def create_session[E: DynamicEndpoint, BodyRq: BodyModel, BodyRs: BodyModel](
    endpoint: type[E],
    *,
    request: type[BodyRq] = EmptyModel,
    response: type[BodyRs] = DynamicBodyModel,
) -> type[Session]:
    #
    # Sanity checks
    if endpoint.verb == "GET":
        assert request is EmptyModel, "GET requests must have an empty request body"
    if endpoint.verb == "POST":
        assert request is not EmptyModel, "POST requests must have a request body"

    class _Request(SessionRequest[request, endpoint]):
        _config = RequestConfig(endpoint=endpoint, body=request)

    class _Response(SessionResponse[response]):
        _config = ResponseConfig(body=response)

    @serialize
    class _Session(Session[_Request, _Response]):
        pass

    return _Session
