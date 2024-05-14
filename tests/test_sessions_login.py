import json
from typing import cast
from unittest.mock import Mock

import httpx
import pytest
from pytest_httpx import HTTPXMock

from pyicloud.constants import AppleCookies as Jar
from pyicloud.constants import AppleHeaders as Headers
from pyicloud.constants import Endpoints
from pyicloud.models.cookies import Cookies
from pyicloud.models.settings import Settings
from pyicloud.sessions.httpx import iAsyncClient
from pyicloud.sessions.login import iLogin
from tests.const import (
    AUTHENTICATED_USER,
    INVALID_PASSWORD,
    REQUEST_ID,
    REQUIRES_2FA_TOKEN,
    REQUIRES_2FA_USER,
    VALID_PASSWORD,
    VALID_TOKEN,
    VALID_USERS,
)

from .const_cookies import (
    LOGIN_AASP,
    LOGIN_REQUEST_COOKIES,
    LOGIN_RESPONSE_COOKIES,
)
from .const_login import (
    AUTH_KO_BAD_PASSWORD,
    AUTH_OK,
    LOGIN_WORKING,
)


@pytest.fixture
def login_cookies():
    return Cookies.model_validate([cookie.value for cookie in LOGIN_REQUEST_COOKIES])


@pytest.fixture
def authenticated_user_settings():
    return Settings.model_validate(
        {
            "account": {
                "username": AUTHENTICATED_USER,
                "password": VALID_PASSWORD,
            },
        },
    )


@pytest.mark.asyncio
async def test_login_request(login_cookies, authenticated_user_settings):
    cookies, settings = login_cookies, authenticated_user_settings

    async with iLogin(settings=settings, cookies=cookies, settings_read=False) as session:
        # BaseSession Headers
        assert {
            "accept": "application/json",
            "origin": Endpoints.HOME,
            "content-type": "application/json",
        }.items() <= session.headers.items(), "Base Headers do not match"

        # Login Headers
        assert {
            "content-type": "application/json",
            "x-apple-oauth-client-id": "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d",
            "x-apple-oauth-client-type": "firstPartyAuth",
            "x-apple-oauth-redirect-uri": Endpoints.HOME,
            "x-apple-oauth-require-grant-code": "true",
            "x-apple-oauth-response-type": "code",
            "x-apple-oauth-response-mode": "web_message",
            "x-apple-oauth-state": settings.client_settings.client_id,
            "x-apple-widget-key": "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d",
        }.items() <= session.headers.items(), "Login Headers do not match"

        # Login Cookies
        assert (
            cookies.model_dump(include=["dslang", "site"]).items()
            <= {name: session.cookies[name] for name in session.cookies}.items()
        )

        # Login Params
        assert {
            "isRememberMeEnabled": "true",
        }.items() <= session.params.items(), "Login Params do not match"

        # Login Body
        assert {
            "rememberMe": True,
            "accountName": AUTHENTICATED_USER,
            "trustTokens": [],
            "password": VALID_PASSWORD,
        }.items() <= cast(iAsyncClient, session).json_data.items(), "Login Body do not match"


async def sigin_response_callback(request: httpx.Request):
    headers = {Headers.REQUEST_ID: REQUEST_ID}
    status_code = 500  # Interal error

    # Success path
    data = json.loads(request.content)
    if data.get("accountName") in VALID_USERS and data.get("password") == VALID_PASSWORD:
        status_code = 200
        headers.update({Headers.SESSION_TOKEN: VALID_TOKEN, Headers.COUNTRY_CODE: "FRA"})
        cookies = LOGIN_RESPONSE_COOKIES
        content = LOGIN_WORKING
        # 2FA path
        if data.get("accountName") == REQUIRES_2FA_USER:
            status_code = 204
            headers.update({Headers.SESSION_TOKEN: REQUIRES_2FA_TOKEN})
            content = AUTH_OK
    # Error Path
    else:
        status_code = 401
        content = AUTH_KO_BAD_PASSWORD
        cookies = LOGIN_REQUEST_COOKIES + [LOGIN_AASP]

    # If status_code is 500, test will fail
    assert status_code != 500
    headers = [(key, value) for key, value in headers.items()] + cookies
    return httpx.Response(headers=headers, status_code=status_code, json=content)


@pytest.fixture
def httpx_login_mock(httpx_mock: HTTPXMock) -> HTTPXMock:
    matchers = {
        "url": iLogin.ENDPOINT,
        "method": "POST",
    }
    httpx_mock.add_callback(sigin_response_callback, **matchers)
    return httpx_mock


@pytest.mark.asyncio
async def test_login_success(
    login_cookies,
    authenticated_user_settings,
    httpx_login_mock: HTTPXMock,
):
    cookies, settings = login_cookies, authenticated_user_settings

    ilogin = iLogin(settings=settings, cookies=cookies, settings_read=False)
    async with ilogin as session:
        # We monkeypatch httpxclient to accept a json_data property. If predsent and not None,
        # it will be used as the json request body. If a json attribute is present, it will be used
        # instead of the json_data property

        session_mock = Mock()
        settings.token.events.session.connect(session_mock)

        # Fetch httpx pure response. This is the response object returned by the httpx client.
        response = await session.post(iLogin.ENDPOINT)

        # Thre's a hook to httpx response to read response contents and store internally. But,
        # parsing response is only performance when response proerty on iLogin is called
        assert settings.token.session is None
        session_mock.assert_not_called()

        # HTTPX Response Status Code
        assert response.status_code == 200

        # HTTPX Response Headers
        assert {
            Headers.REQUEST_ID: REQUEST_ID,
            Headers.COUNTRY_CODE: "FRA",
            Headers.SESSION_TOKEN: VALID_TOKEN,
        }.items() <= response.headers.items()

        # HTTPX Response Cookies Cookie
        assert {
            Jar.DSLANG: "US-EN",
            Jar.SITE: "USA",
            Jar.AASP: "login_aasp",
            Jar.ACN01: "acn01_value",
        }.items() <= dict(response.cookies).items()

    assert bool(ilogin.response) is True
    assert ilogin.response.headers.country_code == "FRA"
    assert ilogin.response.headers.session_token == VALID_TOKEN

    # Settings is updated with the new session token when the context manager is exited
    assert settings.token.session == VALID_TOKEN
    session_mock.assert_called_once_with(VALID_TOKEN)


# @pytest.mark.asyncio
# def test_login_2fa_user_success(httpx_login_mock: HTTPXMock):
#     matchers = {
#         "url": iLogin.ENDPOINT,
#         "method": "POST",
#         "headers": {},
#     }
#     httpx_mock.add_response(json=AUTH_OK, status_code=200, **matchers)


# def test_login_invalid_username(httpx_mock):
#     pass


@pytest.fixture
def authenticated_user_bad_password_settings():
    return Settings.model_validate(
        {
            "account": {
                "username": AUTHENTICATED_USER,
                "password": INVALID_PASSWORD,
            },
        },
    )


@pytest.mark.asyncio
async def test_login_bad_credentials(
    login_cookies,
    authenticated_user_bad_password_settings,
    httpx_login_mock: HTTPXMock,
):
    cookies, settings = login_cookies, authenticated_user_bad_password_settings

    ilogin = iLogin(settings=settings, cookies=cookies, settings_read=False)
    async with ilogin as session:
        # We monkeypatch httpxclient to accept a json_data property. If predsent and not None,
        # it will be used as the json request body. If a json attribute is present, it will be used
        # instead of the json_data property

        session_mock = Mock()
        settings.token.events.session.connect(session_mock)

        # Fetch httpx pure response. This is the response object returned by the httpx client.
        response = await session.post(iLogin.ENDPOINT)

        # Thre's a hook to httpx response to read response contents and store internally. But,
        # parsing response is only performance when response proerty on iLogin is called
        assert settings.token.session is None
        session_mock.assert_not_called()

        # HTTPX Response Status Code
        assert response.status_code == 401

        # HTTPX Response Headers
        assert {
            Headers.REQUEST_ID: REQUEST_ID,
        }.items() <= response.headers.items()

        # HTTPX Response Cookies Cookie
        assert {
            Jar.DSLANG: "US-EN",
            Jar.SITE: "USA",
            Jar.AASP: "login_aasp",
        }.items() <= response.cookies.items()

    assert bool(ilogin.response) is False
    assert ilogin.response.headers.country_code is None
    assert ilogin.response.headers.session_token is None

    # Settings is updated with the new session token when the context manager is exited
    assert len(ilogin.response.errors) == 1
    assert ilogin.response.errors[0].code == -20101


# @pytest.mark.asyncio
# async def test_iLogin_exit(mock_config, mock_httpx):
#     with patch("pyicloud.sessions.login.BaseSession.__aexit__", new_callable=AsyncMock):
#         login = iLogin(mock_config)
#         login._httpx = mock_httpx
#         login._response = AsyncMock(dump_cookies=AsyncMock(), dump_settings=AsyncMock())

#         await login.__aexit__(None, None, None)

#         login._response.dump_cookies.assert_called_once_with(mock_config, [mock_config["cookies.SIGNIN_COOKIES"]])
#         login._response.dump_settings.assert_called_once_with(mock_config)


# def test_iLogin_response_cls(mock_config):
#     login = iLogin(mock_config)
#     assert login.response_cls == LoginResponse
