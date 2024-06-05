from __future__ import annotations

from typing import Annotated, Any, Literal, Sequence, Type, cast, override

import httpx
from pydantic import ConfigDict, Field, model_validator

from pyicloud.constants import AppleHeaders as Header
from pyicloud.constants import Endpoints, iCloud
from pyicloud.models.body import BodyModel
from pyicloud.models.cookies import CookiesModel
from pyicloud.models.headers import HeadersModel
from pyicloud.models.types import (
    AaspType,
    Acn01Type,
    AuthAttributesType,
    CountryCodeType,
    DslangCookieType,
    Meta,
    PasswordType,
    RequestIdType,
    ScntType,
    SessionIdType,
    SessionTokenType,
    SiteCookieType,
    TrustTokenEligibleType,
    TrustTokenType,
    UsernameType,
)
from pyicloud.sessions.base import (
    BaseRequest,
    BaseResponse,
    Endpoint,
    OAuthTransport,
    RequestConfig,
    ResponseConfig,
)
from pyicloud.sessions.decorators import serialize


##
# Request
##
class SignInEndpoint(Endpoint):
    url = Endpoints.SIGNIN
    verb = "POST"
    content_type = "application/json"

    # Query parameters
    remember_me: Annotated[bool, Meta(params="isRememberMeEnabled")] = True


class SignInRequestHeaders(HeadersModel):
    oauth_client_id: Annotated[str, Meta(header=Header.OAUTH_CLIENT_ID)] = iCloud.WIDGET_KEY
    oauth_client_type: Annotated[str, Meta(header=Header.OAUTH_CLIENT_TYPE)] = iCloud.CLIENT_TYPE
    oauth_redirect_uri: Annotated[str, Meta(header=Header.OAUTH_REDIRECT_URI)] = iCloud.REDIRECT_URI
    oauth_require_grant_code: Annotated[str, Meta(header=Header.OAUTH_REQUIRE_GRANT_CODE)] = iCloud.REQUIRE_GRANT_CODE
    oauth_response_mode: Annotated[str, Meta(header=Header.OAUTH_RESPONSE_MODE)] = iCloud.RESPONSE_MODE
    oauth_response_type: Annotated[str, Meta(header=Header.OAUTH_RESPONSE_TYPE)] = iCloud.RESPONSE_TYPE
    oauth_state: Annotated[str, Meta(header=Header.OAUTH_STATE, config="client_settings.client_id")] = cast(Any, None)
    widget_key: Annotated[str, Meta(header=Header.WIDGET_KEY)] = iCloud.WIDGET_KEY

    @model_validator(mode="before")
    @classmethod
    def model_validate_set_defaults(cls, data: dict[str, Any]) -> dict[str, Any]:
        data.setdefault("accept", "application/json")
        data.setdefault("origin", Endpoints.HOME)
        data.setdefault("content-type", "application/json")
        return data


class SignInRequestCookies(CookiesModel):
    dslang: DslangCookieType = Field(default=...)
    site: SiteCookieType = Field(default=...)


class SignInRequestBody(BodyModel):
    # Body parameters
    account_name: UsernameType
    password: PasswordType | None = None
    trust_tokens: TrustTokenType = None
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
        content = content or {}
        assert isinstance(content, dict), "Content must be a dictionary."

        # Upate json data
        super().dump_content(
            content,
            include=["password", "accountName", "trustTokens"],
            exclude=exclude,
            exclude_unset=exclude_unset,
            exclude_defaults=exclude_defaults,
            context=context,
        )
        # Prepare Body
        content = {
            "rememberMe": True,
            "accountName": self._settings.account.username,
            "trustTokens": [],
        }
        if self._settings.account.password:
            content["password"] = cast(Any, self._settings.account.password).get_secret_value()
        if self._settings.token.trust:
            content["trustTokens"] = [self._settings.token.trust]
        # updated
        return content

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
