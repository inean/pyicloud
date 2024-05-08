from __future__ import annotations

from typing import Literal, Type, cast

from pyicloud.constants import Endpoints
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
from pyicloud.sessions.base import BaseRequest, BaseResponse, BaseSession, ResponseConfig
from pyicloud.sessions.httpx import allow_verbs, iAsyncClient, serialize


class LoggedHeaders(HeadersModel):
    country_code: CountryCodeType | None = None
    trust_token: TrustTokenType | None = None
    turst_token_eligible: TrustTokenEligibleType | None = None
    session_token: SessionTokenType | None = None
    session_id: SessionIdType | None = None
    scnt: ScntType | None = None


class LoggedCookies(InitCookiesModel):
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


class LoggedResponse(BaseResponse):
    _config = ResponseConfig(
        headers=LoggedHeaders,
        cookies=LoggedCookies,
    )

    def __bool__(self):
        """Return True if the response is successful."""
        # if a 409 is returned, the user login was successfull but a 2FA is needed
        return True if self.status_code == 409 else super().__bool__()


class LoggedRequest(BaseRequest):
    # Header Fields
    scnt: ScntType
    session_id: SessionIdType

    # Body Fields
    security_code: str


@serialize
@allow_verbs("post")
class VerifyHSA2Code(BaseSession[LoggedRequest, LoggedResponse]):
    ENDPOINT = f"{Endpoints.AUTH}/verify/trusteddevice/securitycode"

    async def __aenter__(self):
        # Set Headers
        self.update_headers(self._httpx.headers)
        # Set Cookies
        self.update_cookies(self._httpx.cookies)
        # Prepare Body
        json_data = {
            "securityCode": {
                "code": self.request.security_code,
            }
        }
        cast(iAsyncClient, self._httpx).json_data = json_data

        # Return the httpx client
        return await super().__aenter__()

    async def __aexit__(self, exc_type, exc, tb):
        await super().__aexit__(exc_type, exc, tb)
        self.update_session()

    @property
    def response_cls(self) -> Type[LoggedResponse]:
        return LoggedResponse

    @property
    def request_cls(self) -> Type[LoggedRequest]:
        return LoggedRequest
