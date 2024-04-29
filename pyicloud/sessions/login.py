from __future__ import annotations

from typing import Literal, Type, cast, override

from pyicloud.constants import AppleHeaders as Headers
from pyicloud.constants import Endpoints
from pyicloud.models.cookies import InitCookiesModel
from pyicloud.models.types import (
    AaspType,
    Acn01Type,
    CountryCodeType,
    Field,
    ScntType,
    SessionIdType,
    SessionTokenType,
    TrustTokenType,
    XAppleDsWebSessionTokenType,
    XAppleUniqueClientIdType,
    XAppleWebauthHsaLoginType,
    XAppleWebauthLoginType,
    XAppleWebauthUserType,
    XAppleWebauthValidateType,
)
from pyicloud.sessions.base import BaseResponse, BaseSession, HeadersModel, ResponseConfig, SettingsModel
from pyicloud.sessions.httpx import allow_verbs, iAsyncClient, serialize


class LoginHeaders(HeadersModel):
    country_code: CountryCodeType = Field(default=...)
    trust_token: TrustTokenType | None = None
    session_token: SessionTokenType | None = None
    session_id: SessionIdType | None = None
    scnt: ScntType | None = None


class LoginCookies(InitCookiesModel):
    aasp: AaspType
    acn01: Acn01Type
    client_id: XAppleUniqueClientIdType
    webauth_login: XAppleWebauthLoginType
    webauth_user: XAppleWebauthUserType
    webauth_validate: XAppleWebauthValidateType
    webauth_hsa_login: XAppleWebauthHsaLoginType
    session_token: XAppleDsWebSessionTokenType


class LoginSettings(SettingsModel):
    auth_type: Literal["hsa2"] | None = Field(alias="authType")


class LoginResponse(BaseResponse):
    _config = ResponseConfig(
        headers=LoginHeaders,
        cookies=LoginCookies,
    )

    def __bool__(self):
        """Return True if the response is successful."""
        # if a 409 is returned, the user login was successfull but a 2FA is needed
        return True if self.status_code == 409 else super().__bool__()


@serialize
@allow_verbs("post")
class iLogin(BaseSession[LoginResponse]):
    ENDPOINT = "https://idmsa.apple.com/appleauth/auth/signin"

    async def __aenter__(self):
        await super().__aenter__()
        # Set params
        self._httpx.params = {"isRememberMeEnabled": "true"}
        # Prepare Body
        json_data = {
            "rememberMe": True,
            "accountName": self._settings.account.username,
            "trustTokens": [],
        }
        if self._settings.account.password:
            json_data["password"] = self._settings.account.password.get_secret_value()
        if self._settings.token.trust:
            json_data["trustTokens"] = [self._settings.token.trust]

        cast(iAsyncClient, self._httpx).json_data = json_data
        return self._httpx

    @property
    def response_cls(self) -> Type[LoginResponse]:
        return LoginResponse

    @override
    def update_headers(self, headers):
        super().update_headers(headers)

        new_headers = {
            "content-type": "application/json",
            Headers.OAUTH_CLIENT_ID: "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d",
            Headers.OAUTH_CLIENT_TYPE: "firstPartyAuth",
            Headers.OAUTH_REDIRECT_URI: Endpoints.HOME,
            Headers.OAUTH_REQUIRE_GRANT_CODE: "true",
            Headers.OAUTH_RESPONSE_TYPE: "code",
            Headers.OAUTH_RESPONSE_MODE: "web_message",
            Headers.OAUTH_STATE: self._settings["client_settings.client_id"],
            Headers.WIDGET_KEY: "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d",
        }

        for key, value in new_headers.items():
            headers.setdefault(key.lower(), value)


class iRefreshLogin(iLogin):
    """Re-Login to iCloud using available session data."""

    async def __aenter__(self):
        await super().__aenter__()
        # Update headers for POST Request
        headers = {}
        if scnt := self._settings["client_settings.scnt"]:
            headers[Headers.SCNT] = scnt
        if ssid := self._settings["account.session_id"]:
            headers[Headers.SESSION_ID] = ssid
        # Set headers
        self._httpx.headers.update(headers)
        # Update body
        if trust_token := self._settings["tokens.trust"]:
            cast(iAsyncClient, self._httpx).json_data["trustTokens"] = [trust_token]
        return self._httpx
