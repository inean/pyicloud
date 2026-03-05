from __future__ import annotations

from typing import TYPE_CHECKING, cast, overload
from unittest.mock import patch

import httpx
import pytest
from pytest_lazy_fixtures import lf

from pyicloud.constants import AppleCookies as Jar
from pyicloud.constants import Endpoints
from pyicloud.models.cookies import Cookies
from pyicloud.models.settings import Settings
from pyicloud.sessions.validate import Validate, ValidateRequest
from pyicloud.utils import mapping
from tests import process_cookies
from tests.const import AUTHENTICATED_USER, INVALID_TOKEN, SCNT, SESSION_ID, VALID_TOKEN
from tests.const_auth import (
    SESSION_RESPONSE_BODY_2FA,
    SESSION_RESPONSE_BODY_OK,
    VALIDATE_REQUEST_COOKIES,
    VALIDATE_REQUEST_HEADERS,
    VALIDATE_RESPONSE_COOKIES_KO,
    VALIDATE_RESPONSE_COOKIES_OK,
    VALIDATE_RESPONSE_HEADERS_KO,
    VALIDATE_RESPONSE_HEADERS_OK,
)

if TYPE_CHECKING:

    class Request(httpx.Request):
        cookies: dict[str, str]
else:
    Request = httpx.Request


@overload
def validate_handler(request: httpx.Request) -> httpx.Response: ...


@overload
def validate_handler(request: Request) -> httpx.Response: ...


@process_cookies
def validate_handler(request: Request | httpx.Request) -> httpx.Response:
    assert request.method == "POST"
    assert str(request.url).startswith(Endpoints.VALIDATE)

    status_code = 500  # Internal error
    while True:
        # Malformed request
        if not mapping.compare(dict(VALIDATE_REQUEST_HEADERS), dict(request.headers)):
            content = b""
            break
        if not mapping.compare(dict(map(tuple, VALIDATE_REQUEST_COOKIES)), cast(Request, request).cookies):
            content = b""
            break

        # Success path
        status_code = 200
        headers = VALIDATE_RESPONSE_HEADERS_OK
        cookies = VALIDATE_RESPONSE_COOKIES_OK

        if cast(Request, request).cookies.get(Jar.WEBAUTH_HSA_TRUST) == VALID_TOKEN:
            content = SESSION_RESPONSE_BODY_2FA
            break
        if cast(Request, request).cookies.get(Jar.WEBAUTH_TOKEN) == VALID_TOKEN:
            content = SESSION_RESPONSE_BODY_OK
            break

        # Error Path
        status_code = 404
        headers = VALIDATE_RESPONSE_HEADERS_KO
        cookies = VALIDATE_RESPONSE_COOKIES_KO
        content = b""
        break

    # If status_code is 500, test will fail
    assert status_code != 500
    headers = list(headers.items()) + list(map(lambda o: o.items(), cookies))
    return httpx.Response(headers=headers, status_code=status_code, json=content if content else None)


@pytest.fixture
def validate_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(mounts={Endpoints.VALIDATE: httpx.MockTransport(validate_handler)})


@pytest.fixture
def validate_settings():
    with patch("locale.getlocale", return_value=["en_US", "UTF-8"]):
        return Settings.model_validate(
            {
                "account": {
                    "username": AUTHENTICATED_USER,
                    "session_id": SESSION_ID,
                },
                "token": {
                    "session": VALID_TOKEN,
                    "trust": VALID_TOKEN,
                },
                "client_settings": {
                    "scnt": SCNT,
                },
            },
        )


@pytest.fixture
def validate_cookies_trust() -> Cookies:
    return Cookies.model_validate(
        {cookie.name: {"name": cookie.name, "value": cookie.value} for cookie in VALIDATE_REQUEST_COOKIES}
    )


@pytest.fixture
def validate_cookies_token() -> Cookies:
    cookies = Cookies.model_validate(
        {cookie.name: {"name": cookie.name, "value": cookie.value} for cookie in VALIDATE_REQUEST_COOKIES}
    )
    cookies[Jar.WEBAUTH_HSA_TRUST] = INVALID_TOKEN
    cookies[Jar.WEBAUTH_TOKEN] = VALID_TOKEN
    return cookies


@pytest.fixture
def validate_cookies_invalid() -> Cookies:
    cookies = Cookies.model_validate(
        {cookie.name: {"name": cookie.name, "value": cookie.value} for cookie in VALIDATE_REQUEST_COOKIES}
    )
    cookies[Jar.WEBAUTH_HSA_TRUST] = INVALID_TOKEN
    cookies[Jar.WEBAUTH_TOKEN] = INVALID_TOKEN
    return cookies


@pytest.fixture
def user_trust(validate_settings, validate_cookies_trust, validate_client):
    return Validate(
        settings=validate_settings,
        cookies=validate_cookies_trust,
        client=validate_client,
    )


@pytest.fixture
def user_token(validate_settings, validate_cookies_token, validate_client):
    return Validate(
        settings=validate_settings,
        cookies=validate_cookies_token,
        client=validate_client,
    )


@pytest.fixture
def user_invalid(validate_settings, validate_cookies_invalid, validate_client):
    return Validate(
        settings=validate_settings,
        cookies=validate_cookies_invalid,
        client=validate_client,
    )


def test_validate_request_classes(user_trust: Validate):
    assert isinstance(user_trust.request, ValidateRequest)


async def test_validate_request_headers(user_trust: Validate):
    headers = user_trust.dump_headers()
    assert {
        "accept": "application/json",
        "origin": Endpoints.HOME,
        "content-type": "application/json",
        "x-apple-id-session-id": SESSION_ID,
        "scnt": SCNT,
    }.items() <= headers.items()


async def test_validate_request_cookies(user_trust: Validate):
    expected_cookie_names = {cookie.name for cookie in VALIDATE_REQUEST_COOKIES}
    assert expected_cookie_names.issubset(user_trust.dump_cookies().keys())


async def test_validate_request_body(user_trust: Validate):
    assert user_trust.dump_content() == {}


def test_validate_request_accepts_minimal_cookie_set(validate_settings: Settings):
    minimal = Cookies.model_validate(
        {
            Jar.DSLANG: {"name": Jar.DSLANG, "value": "US-EN"},
            Jar.SITE: {"name": Jar.SITE, "value": "USA"},
            Jar.WEBAUTH_USER: {"name": Jar.WEBAUTH_USER, "value": "webauth_user_value"},
            Jar.WEBAUTH_TOKEN: {"name": Jar.WEBAUTH_TOKEN, "value": VALID_TOKEN},
            Jar.WEBAUTH_VALIDATE: {"name": Jar.WEBAUTH_VALIDATE, "value": VALID_TOKEN},
            Jar.WEB_SESSION_TOKEN: {"name": Jar.WEB_SESSION_TOKEN, "value": "session_token"},
        }
    )
    user = Validate(settings=validate_settings, cookies=minimal)
    request = user.request.create_request()
    assert request.url == Endpoints.VALIDATE


@pytest.fixture
async def response_factory():
    async def _response(user: Validate):
        response = await user._client.post(
            url=Endpoints.VALIDATE,
            headers=user.dump_headers(),
            cookies=user.dump_cookies(),
            json=user.dump_content(),
        )
        await response.aread()
        return response

    return _response


@pytest.mark.parametrize(
    "user, expected_status",
    [
        (lf("user_trust"), 200),
        (lf("user_token"), 200),
        (lf("user_invalid"), 404),
    ],
)
async def test_validate_response_status_codes(user, expected_status, response_factory):
    response = await response_factory(user)
    assert response.status_code == expected_status


async def test_validate_response_2fa(user_trust: Validate, response_factory):
    response = await response_factory(user_trust)
    assert response.json() == SESSION_RESPONSE_BODY_2FA


async def test_validate_response_session(user_token: Validate, response_factory):
    response = await response_factory(user_token)
    assert response.json() == SESSION_RESPONSE_BODY_OK


async def test_validate_response_invalid(user_invalid: Validate, response_factory):
    response = await response_factory(user_invalid)
    assert response.status_code == 404
    assert response.content == b""
