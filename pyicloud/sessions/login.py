from __future__ import annotations

from typing import Literal, Type, cast

from pyicloud.constants import AppleHeaders as Headers
from pyicloud.models.cookies import InitCookiesModel
from pyicloud.models.headers import HeadersModel
from pyicloud.models.settings import SettingsModel
from pyicloud.models.types import (
    AaspType,
    Acn01Type,
    CountryCodeType,
    Field,
    ScntType,
    SessionIdType,
    SessionTokenType,
    TrustTokenEligibleType,
    TrustTokenType,
)
from pyicloud.sessions.base import BaseResponse, OAuthSession, ResponseConfig
from pyicloud.sessions.httpx import allow_verbs, iAsyncClient, serialize


class LoginHeaders(HeadersModel):
    country_code: CountryCodeType | None = None
    trust_token: TrustTokenType | None = None
    turst_token_eligible: TrustTokenEligibleType | None = None
    session_token: SessionTokenType | None = None
    session_id: SessionIdType | None = None
    scnt: ScntType | None = None


class LoginCookies(InitCookiesModel):
    acn01: Acn01Type | None = None  # On login error, the acn01 cookie is not returned
    aasp: AaspType


#    client_id: XAppleUniqueClientIdType
#    webauth_login: XAppleWebauthLoginType
#    webauth_user: XAppleWebauthUserType
#    webauth_validate: XAppleWebauthValidateType
#    webauth_hsa_login: XAppleWebauthHsaLoginType

#    session_token: XAppleDsWebSessionTokenType


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
class iLogin(OAuthSession[LoginResponse]):
    ENDPOINT = "https://idmsa.apple.com/appleauth/auth/signin"

    async def __aenter__(self):
        # Set Headers
        self.update_headers(self._httpx.headers)
        # Set Cookies
        self.update_cookies(self._httpx.cookies)
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

        # Return the httpx client
        return await super().__aenter__()

    async def __aexit__(self, exc_type, exc, tb):
        await super().__aexit__(exc_type, exc, tb)
        self.update_session()

    @property
    def response_cls(self) -> Type[LoginResponse]:
        return LoginResponse


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
