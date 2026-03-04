import json
from typing import TYPE_CHECKING, cast, overload
from unittest.mock import patch

import httpx
import pytest

from pyicloud.constants import Endpoints
from pyicloud.models.cookies import Cookies
from pyicloud.models.settings import Settings
from pyicloud.sessions.security_code import SecurityCode, SecurityCodeRequest, SecurityCodeResponse
from pyicloud.utils import mapping
from tests import process_cookies
from tests.const import (
    REQUIRES_2FA_USER,
    SCNT,
    SESSION_ID,
    VALID_2FA_CODE,
    VALID_TOKEN,
)
from tests.const_auth import (
    SECURITY_CODE_REQUEST_COOKIES,
    SECURITY_CODE_REQUEST_HEADERS,
    SECURITY_CODE_RESPONSE_BODY_KO_BAD_SECURITY_CODE,
    SECURITY_CODE_RESPONSE_COOKIES_KO,
    SECURITY_CODE_RESPONSE_COOKIES_OK,
    SECURITY_CODE_RESPONSE_HEADERS_KO,
    SECURITY_CODE_RESPONSE_HEADERS_OK,
)

if TYPE_CHECKING:

    class Request(httpx.Request):
        cookies: dict[str, str]
else:
    Request = httpx.Request


@overload
def security_code_handler(request: httpx.Request) -> httpx.Response: ...


@overload
def security_code_handler(request: Request) -> httpx.Response: ...


@process_cookies
def security_code_handler(request: Request | httpx.Request) -> httpx.Response:
    assert request.method == "POST"
    assert str(request.url).startswith(Endpoints.SECURITY_CODE)

    status_code = 500  # Internal error
    while True:
        # Malformed request
        if not mapping.compare(dict(map(tuple, SECURITY_CODE_REQUEST_HEADERS)), dict(request.headers)):
            content = b""
            break
        if not mapping.compare(dict(map(tuple, SECURITY_CODE_REQUEST_COOKIES)), cast(Request, request).cookies):
            content = b""
            break

        # Success path
        status_code = 204
        headers = SECURITY_CODE_RESPONSE_HEADERS_OK
        cookies = SECURITY_CODE_RESPONSE_COOKIES_OK
        data = json.loads(request.content)

        if data.get("securityCode", {}).get("code", None) == VALID_2FA_CODE:
            content = b""
            break

        # Error Path
        status_code = 400
        headers = SECURITY_CODE_RESPONSE_HEADERS_KO
        cookies = SECURITY_CODE_RESPONSE_COOKIES_KO
        content = SECURITY_CODE_RESPONSE_BODY_KO_BAD_SECURITY_CODE
        break

    # If status_code is 500, test will fail
    assert status_code != 500
    headers = list(headers.items()) + list(map(lambda o: o.items(), cookies))
    return httpx.Response(headers=headers, status_code=status_code, json=content if content else None)


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
    return Cookies.model_validate([cookie._content for cookie in SECURITY_CODE_REQUEST_COOKIES])


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
    async with user as session:
        # Fetch httpx pure response. This is the response object returned by the httpx client.
        _ = await session.send(user.request.create_request())

    assert user.request.body.security_code == VALID_2FA_CODE
    # Test the response_cls property
    assert user.response_cls == SecurityCodeResponse

    # Test the request_cls property
    assert user.request_cls == SecurityCodeRequest
