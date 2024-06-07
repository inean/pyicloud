from __future__ import annotations

from typing import Any, Sequence, Type, override

import httpx
from pydantic import Field, model_validator

from pyicloud.constants import AppleHeaders as Header
from pyicloud.constants import Endpoints
from pyicloud.models.bodies import EmptyModel
from pyicloud.models.cookies import CookiesModel
from pyicloud.models.fields import (
    AaspType,
    Acn01Type,
    AuthAttributesType,
    CountryCodeType,
    DesType,
    DslangCookieType,
    OAuthGrantCodeType,
    RequestIdType,
    ScntType,
    SessionIdType,
    SessionTokenType,
    SiteCookieType,
    TrustTokenType,
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
class TrustEndpoint(Endpoint):
    url = Endpoints.TRUST
    verb = "GET"
    content_type = "application/json"

    # Query parameters


class TrustRequestHeaders(OAuthHeadersModel):
    # Header Fields
    scnt: ScntType
    session_id: SessionIdType

    @model_validator(mode="before")
    @classmethod
    def model_validate_set_defaults(cls, data: dict[str, Any]) -> dict[str, Any]:
        data.setdefault("accept", "application/json")
        data.setdefault("origin", Endpoints.HOME)
        return data


class TrustRequestCookies(CookiesModel):
    dslang: DslangCookieType = Field(default=...)
    site: SiteCookieType = Field(default=...)
    # Cookie Fields
    aasp: AaspType = Field(default=...)
    acn01: Acn01Type = Field(default=...)


class TrustRequestBody(EmptyModel): ...


class TrustRequest(BaseRequest[TrustRequestHeaders, TrustRequestCookies, TrustRequestBody, TrustEndpoint]):
    _config = RequestConfig(
        headers=TrustRequestHeaders,
        cookies=TrustRequestCookies,
        body=TrustRequestBody,
        endpoint=TrustEndpoint,
    )


##
# Response
##
class TrustResponseHeaders(HeadersModel):
    # Required Headers
    request_id: RequestIdType
    scnt: ScntType
    # Required Headers only on successful response
    trust_token: TrustTokenType | None = None
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
    _config = ResponseConfig(
        headers=TrustResponseHeaders,
        cookies=TrustResponseCookies,
        body=TrustResponseBody,
    )

    def __bool__(self):
        """Return True if the response is successful."""
        return self.status_code == 204


##
# Transport
##
@serialize
class Trust(OAuthTransport[TrustRequest, TrustResponse]):
    @property
    def response_cls(self) -> Type[TrustResponse]:
        return TrustResponse

    @property
    def request_cls(self) -> Type[TrustRequest]:
        return TrustRequest

    @override
    def dump_content(
        self,
        content: bytes | dict[str, Any] | None = None,
        *,
        include: Sequence[str] | None = None,
        exclude: Sequence[str] | None = None,
        exclude_unset=True,
        exclude_defaults=False,
        context: Any = None,
    ) -> bytes | dict[str, Any] | None:
        """Update the content for the request."""

        return b""

    @override
    def dump_headers(
        self,
        headers: httpx.Headers | None = None,
        *,
        include: Sequence[str] | None = None,
        exclude: Sequence[str] | None = None,
        exclude_unset=True,
        exclude_defaults=False,
        context: Any = None,
    ) -> httpx.Headers:
        headers = headers or httpx.Headers()
        # Don't set country code header for outbound request
        headers = super().dump_headers(
            headers,
            include=include,
            exclude=exclude,
            exclude_unset=exclude_unset,
            exclude_defaults=exclude_defaults,
            context=context,
        )

        if scnt := self._settings["client_settings.scnt"]:
            headers[Header.SCNT] = scnt
        if ssid := self._settings["account.session_id"]:
            headers[Header.SESSION_ID] = ssid

        return headers
