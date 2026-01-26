from __future__ import annotations

from typing import Annotated, Any, Literal, Sequence, Type, override

import httpx
from pydantic import ConfigDict, Field

from pyicloud.constants import AppleHeaders as Header
from pyicloud.constants import Endpoints
from pyicloud.models.bodies import BodyModel
from pyicloud.models.cookies import CookiesModel
from pyicloud.models.fields import (
    AaspType,
    AcceptType,
    Acn01Type,
    AuthAttributesType,
    ContentTypeType,
    CountryCodeType,
    DslangCookieType,
    Meta,
    OriginType,
    PasswordType,
    RequestIdType,
    ScntType,
    SessionIdType,
    SessionTokenType,
    SiteCookieType,
    TrustTokenEligibleType,
    TrustTokensType,
    UsernameType,
)
from pyicloud.models.headers import HeadersModel, OAuthHeadersModel
from pyicloud.sessions import (
    BaseRequest,
    BaseResponse,
    OAuthTransport,
    RequestConfig,
    ResponseConfig,
    StaticEndpoint,
    serialize,
)


##
# Request
##
class SignInEndpoint(StaticEndpoint):
    endpoint = Endpoints.SIGNIN
    verb = "POST"
    content_type = "application/json"

    # Query parameters
    remember_me: Annotated[bool, Meta(params="isRememberMeEnabled")] = True


class SignInRequestHeaders(OAuthHeadersModel):
    accept: AcceptType = "application/json"
    origin: OriginType = Endpoints.HOME
    content_type: ContentTypeType = "application/json"


class SignInRequestCookies(CookiesModel):
    dslang: DslangCookieType
    site: SiteCookieType


class SignInRequestBody(BodyModel):
    # Body parameters
    account_name: UsernameType
    password: PasswordType | None = None
    trust_tokens: TrustTokensType = None
    remember_me: Annotated[bool, Meta(body="rememberMe")] = True


class SignInRequest(BaseRequest[SignInRequestHeaders, SignInRequestCookies, SignInRequestBody, SignInEndpoint]):
    _config = RequestConfig(
        headers=SignInRequestHeaders,
        cookies=SignInRequestCookies,
        body=SignInRequestBody,
        endpoint=SignInEndpoint,
    )


##
# Response
##
class SignInResponseHeaders(HeadersModel):
    # Required Headers
    request_id: RequestIdType
    scnt: ScntType

    # Required Headers only on successful response
    country_code: CountryCodeType | None = None
    session_id: SessionIdType | None = None
    session_token: SessionTokenType | None = None

    # Optional Headers only present on successful response
    trust_token_eligible: TrustTokenEligibleType | None = None
    auth_attributes: AuthAttributesType | None = None


class SignInResponseCookies(CookiesModel):
    dslang: DslangCookieType
    site: SiteCookieType
    # On login error, the acn01 cookie is not returned
    acn01: Acn01Type | None = None
    # On successful login, the aasp cookie my not be returned if aasp already exists
    aasp: AaspType | None = None


class SignInResponseBody(BodyModel):
    model_config = ConfigDict(extra="allow")

    auth_type: Literal["hsa2"] | None = Field(alias="authType", default=None)


class SignInResponse(BaseResponse[SignInResponseHeaders, SignInResponseCookies, SignInResponseBody]):
    _config = ResponseConfig(
        headers=SignInResponseHeaders,
        cookies=SignInResponseCookies,
        body=SignInResponseBody,
    )

    @override
    @classmethod
    def is_error(cls, status_code):
        """Return True if the response is successful."""
        # if a 409 is returned, the user login was successfull but a 2FA is needed
        return False if status_code == 409 else super().is_error(status_code)


##
# Transport
##
@serialize
class SignIn(OAuthTransport[SignInRequest, SignInResponse]):
    @property
    def response_cls(self) -> Type[SignInResponse]:
        return SignInResponse

    @property
    def request_cls(self) -> Type[SignInRequest]:
        return SignInRequest


@serialize
class FreshSignIn(SignIn):
    """Re-Login to iCloud using available session data."""

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
    ):
        headers = headers or httpx.Headers()
        # Don't set country code header for outbound request
        headers = super().dump_headers(
            headers,
            include=include,
            exclude=exclude or [Header.COUNTRY_CODE],
            exclude_unset=exclude_unset,
            exclude_defaults=exclude_defaults,
            context=context,
        )

        if scnt := self._settings["client_settings.scnt"]:
            headers[Header.SCNT] = scnt
        if ssid := self._settings["account.session_id"]:
            headers[Header.SESSION_ID] = ssid

        return headers
