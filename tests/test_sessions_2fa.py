import json
from typing import cast

import httpx
import pytest

from pyicloud.constants import AppleHeaders as Header
from pyicloud.constants import Endpoints
from pyicloud.models.cookies import Cookies
from pyicloud.models.settings import Settings
from pyicloud.sessions.verify_code import LoggedRequest, LoggedResponse, VerifyHSA2Code
from pyicloud.utils.context import async_context
from tests.const import (
    REQUEST_ID,
    REQUIRES_2FA_USER,
    SCNT,
    SESSION_ID,
    VALID_2FA_CODE,
    VALID_TOKEN,
)

from .const_cookies import (
    BASE_COOKIES,
    LOGGED_COOKIES,
    LOGIN_AASP,
    VERIFY_COOKIES,
)
from .const_login import (
    AUTH_KO_BAD_PASSWORD,
    LOGIN_WORKING,
)


@pytest.fixture
def verify_cookies():
    return Cookies.model_validate([cookie.value for cookie in VERIFY_COOKIES])


@pytest.fixture
def authenticated_2fa_user_settings():
    return Settings.model_validate(
        {
            "account": {
                "username": REQUIRES_2FA_USER,
                "session_id": SESSION_ID,
            },
            "token": {
                "session": VALID_TOKEN,
            },
            "client_settings": {
                "scnt": SCNT,
            },
        }
    )


@pytest.fixture
def httpx_verify_client() -> httpx.AsyncClient:
    matchers = {
        "url": Endpoints.VERIFY,
        "method": "POST",
    }

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == matchers["method"]
        assert str(request.url).startswith(matchers["url"])

        headers = {Header.REQUEST_ID: REQUEST_ID}
        status_code = 500  # Internal error

        # Success path
        data = json.loads(request.content)
        if data.get("securityCode", {}).get("code", None) == VALID_2FA_CODE:
            status_code = 200
            headers.update({Header.SESSION_TOKEN: VALID_TOKEN, Header.COUNTRY_CODE: "FRA"})
            cookies = LOGGED_COOKIES
            content = LOGIN_WORKING
        # Error Path
        else:
            status_code = 401
            content = AUTH_KO_BAD_PASSWORD
            cookies = BASE_COOKIES + [LOGIN_AASP]

        # If status_code is 500, test will fail
        assert status_code != 500
        headers = [(key, value) for key, value in headers.items()] + cookies
        return httpx.Response(headers=headers, status_code=status_code, json=content)

    return httpx.AsyncClient(mounts={matchers["url"]: httpx.MockTransport(handler)})


@pytest.fixture
@async_context(serialize_info={"settings": {"read": False}, "cookies": {"read": False}})
async def verify_success(verify_cookies, authenticated_2fa_user_settings, httpx_verify_client):
    return VerifyHSA2Code(
        settings=authenticated_2fa_user_settings,
        cookies=verify_cookies,
        data={"security_code": VALID_2FA_CODE},
        client=httpx_verify_client,
    )


async def test_verify(verify_cookies, verify_success: VerifyHSA2Code):
    # BaseSession Headers
    headers = verify_success.dump_headers()
    assert {
        "accept": "application/json",
        "origin": Endpoints.HOME,
        "content-type": "application/json",
    }.items() <= headers.items(), "Base Headers do not match"

    # Login Headers
    assert {
        "content-type": "application/json",
        "x-apple-oauth-client-id": "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d",
        "x-apple-oauth-client-type": "firstPartyAuth",
        "x-apple-oauth-redirect-uri": Endpoints.HOME,
        "x-apple-oauth-require-grant-code": "true",
        "x-apple-oauth-response-type": "code",
        "x-apple-oauth-response-mode": "web_message",
        "x-apple-oauth-state": verify_success._settings.client_settings.client_id,
        "x-apple-widget-key": "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d",
    }.items() <= headers.items(), "Login Headers do not match"

    # Login Cookies
    assert verify_cookies.model_dump().items() <= verify_success.dump_cookies().items()

    # Login Body
    assert {
        "securityCode": {"code": VALID_2FA_CODE},
    }.items() <= cast(dict, verify_success.dump_content()).items(), "Verify Body do not match"


async def test_verify_hsa2_request(verify_success):
    settings = verify_success._settings
    cookies = verify_success._cookies

    async with verify_success as session:
        # Fetch httpx pure response. This is the response object returned by the httpx client.
        response = await session.send(verify_success.request.model_dump_httpx_request())

    assert verify_success.request.body.security_code == VALID_2FA_CODE
    # Test the response_cls property
    assert verify_success.response_cls == LoggedResponse

    # Test the request_cls property
    assert verify_success.request_cls == LoggedRequest
