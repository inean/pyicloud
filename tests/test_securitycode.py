import json
from typing import cast
from unittest.mock import patch

import httpx
import pytest

from pyicloud.constants import AppleHeaders as Header
from pyicloud.constants import Endpoints
from pyicloud.models.cookies import Cookies
from pyicloud.models.settings import Settings
from pyicloud.sessions.securitycode import SecurityCode, SecurityCodeRequest, SecurityCodeResponse
from tests.const import (
    REQUEST_ID,
    REQUIRES_2FA_USER,
    SCNT,
    SESSION_ID,
    VALID_2FA_CODE,
    VALID_TOKEN,
)

from .const_auth import (
    AUTH_KO_BAD_SECURITY_CODE,
    BASE_COOKIES,
    SECURITY_CODE_COOKIES,
)


def security_code_handler(request: httpx.Request) -> httpx.Response:
    assert request.method == "POST"
    assert str(request.url).startswith(Endpoints.SECURITY_CODE)

    headers = {Header.REQUEST_ID: REQUEST_ID, Header.SCNT: SCNT}
    status_code = 500  # Internal error

    # Success path
    data = json.loads(request.content)
    if data.get("securityCode", {}).get("code", None) == VALID_2FA_CODE:
        status_code = 204
        headers.update({Header.SESSION_TOKEN: VALID_TOKEN, Header.COUNTRY_CODE: "FRA"})
        cookies = BASE_COOKIES
        content = ""
    # Error Path
    else:
        headers.update({Header.SCNT: SCNT})
        status_code = 400
        cookies = BASE_COOKIES
        content = AUTH_KO_BAD_SECURITY_CODE

    # If status_code is 500, test will fail
    assert status_code != 500
    headers = [(key, value) for key, value in headers.items()] + cookies
    return httpx.Response(headers=headers, status_code=status_code, json=content)


@pytest.fixture
def security_code_settings():
    with patch("locale.getlocale", return_value=["en_US", "UTF-8"]):
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
def security_code_cookies():
    return Cookies.model_validate([cookie.value for cookie in SECURITY_CODE_COOKIES])


@pytest.fixture
def httpx_security_code_client() -> httpx.AsyncClient:
    matchers = {
        "url": Endpoints.SECURITY_CODE,
        "method": "POST",
    }
    return httpx.AsyncClient(mounts={matchers["url"]: httpx.MockTransport(security_code_handler)})


@pytest.fixture
async def user(security_code_cookies, security_code_settings, httpx_security_code_client):
    return SecurityCode(
        settings=security_code_settings,
        cookies=security_code_cookies,
        data={"security_code": VALID_2FA_CODE},
        client=httpx_security_code_client,
    )


async def test_security_code_request(security_code_cookies, user: SecurityCode):
    # BaseSession Headers
    headers = user.dump_headers()
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
        "x-apple-oauth-state": user._settings.client_settings.client_id,
        "x-apple-widget-key": "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d",
    }.items() <= headers.items(), "Login Headers do not match"

    # Login Cookies
    with patch("locale.getlocale", return_value="en_US"):
        assert security_code_cookies.model_dump().items() <= user.dump_cookies().items()

    # Login Body
    assert {
        "securityCode": {"code": VALID_2FA_CODE},
    }.items() <= cast(dict, user.dump_content()).items(), "Verify Body do not match"


async def test_security_code_from_models(user):
    settings = user._settings
    cookies = user._cookies

    async with user as session:
        # Fetch httpx pure response. This is the response object returned by the httpx client.
        response = await session.send(user.request.model_dump_httpx_request())

    assert user.request.body.security_code == VALID_2FA_CODE
    # Test the response_cls property
    assert user.response_cls == SecurityCodeResponse

    # Test the request_cls property
    assert user.request_cls == SecurityCodeRequest
