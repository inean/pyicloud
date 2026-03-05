from __future__ import annotations

from typing import Any, Protocol, Type, TypeVar

from httpx import AsyncClient

from pyicloud.constants import Endpoints
from pyicloud.models.bodies import BodyModel, DynamicBodyModel, EmptyModel
from pyicloud.models.cookies import CookiesModel
from pyicloud.models.fields import (
    AcceptType,
    OriginType,
    ScntType,
    SessionIdType,
    DslangCookieType,
    SiteCookieType,
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
    DynamicEndpoint,
    OAuthTransport,
    RequestConfig,
    ResponseConfig,
    serialize,
)


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
    webauth_hsa_trust: XAppleWebauthHsaTrustType | None = None
    webauth_user: XAppleWebauthUserType | None = None
    webauth_token: XAppleWebauthTokenType
    webauth_validate: XAppleWebauthValidateType
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


def create_session(
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
        @property
        def response_cls(self) -> Type[_Response]:
            return _Response

        @property
        def request_cls(self) -> Type[_Request]:
            return _Request

    return _Session
