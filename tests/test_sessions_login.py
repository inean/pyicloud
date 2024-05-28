import json
from typing import cast
from unittest.mock import Mock, patch

import httpx
import pytest

from pyicloud.constants import AppleCookies as Jar
from pyicloud.constants import AppleHeaders as Header
from pyicloud.constants import Endpoints
from pyicloud.models.cookies import Cookies
from pyicloud.models.settings import Settings
from pyicloud.sessions.base import BodyModel, CookiesModel, HeadersModel
from pyicloud.sessions.login import Init, InitRequest, InitResponse
from pyicloud.utils.context import async_context
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
    BASE_COOKIES,
    LOGGED_COOKIES,
    LOGIN_AASP,
)
from .const_login import (
    AUTH_KO_BAD_PASSWORD,
    AUTH_OK,
    LOGIN_WORKING,
)


@pytest.fixture
def init_cookies():
    return Cookies.model_validate([cookie.value for cookie in BASE_COOKIES])


@pytest.fixture
def authenticated_user_settings():
    with patch("locale.getlocale", return_value=["en_US", "UTF-8"]):
        return Settings.model_validate(
            {
                "account": {
                    "username": AUTHENTICATED_USER,
                    "password": VALID_PASSWORD,
                },
            },
        )


@pytest.fixture
def httpx_login_client() -> httpx.AsyncClient:
    matchers = {
        "url": Endpoints.SIGIN,
        "method": "POST",
    }

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == matchers["method"]
        assert str(request.url).startswith(matchers["url"])

        headers = {Header.REQUEST_ID: REQUEST_ID}
        status_code = 500  # Internal error

        # Success path
        data = json.loads(request.content)
        if data.get("accountName") in VALID_USERS and data.get("password") == VALID_PASSWORD:
            status_code = 200
            headers.update({Header.SESSION_TOKEN: VALID_TOKEN, Header.COUNTRY_CODE: "FRA"})
            cookies = LOGGED_COOKIES
            content = LOGIN_WORKING
            # 2FA path
            if data.get("accountName") == REQUIRES_2FA_USER:
                status_code = 409
                headers.update({Header.SESSION_TOKEN: REQUIRES_2FA_TOKEN})
                content = AUTH_OK
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
@async_context(serialize_info={"settings": {"read": False}})
async def user_without_cookies(init_cookies, authenticated_user_settings, httpx_login_client):
    return Init(
        settings=authenticated_user_settings,
        cookies=init_cookies,
        client=httpx_login_client,
    )


@pytest.fixture
@async_context(serialize_info={"settings": {"read": False}})
async def user(authenticated_user_settings, httpx_login_client):
    return Init(
        settings=authenticated_user_settings,
        cookies=Cookies({}),
        client=httpx_login_client,
    )


async def test_login(user_without_cookies: Init):
    # BaseSession Headers
    headers = user_without_cookies.dump_headers()
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
        "x-apple-oauth-state": user_without_cookies._settings.client_settings.client_id,
        "x-apple-widget-key": "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d",
    }.items() <= headers.items(), "Login Headers do not match"

    # Login Cookies
    with patch("locale.getlocale", return_value="en_US"):
        assert {
            Jar.DSLANG: "US-EN",
            Jar.SITE: "USA",
        }.items() <= user_without_cookies.dump_cookies(include=["dslang", "site"]).items()

    # Login Body
    assert {
        "rememberMe": True,
        "accountName": AUTHENTICATED_USER,
        "trustTokens": [],
        "password": VALID_PASSWORD,
    }.items() <= cast(dict, user_without_cookies.dump_content()).items(), "Login Body do not match"


async def test_login_request(user):
    assert user.request_cls == InitRequest
    assert user.response_cls == InitResponse

    request = user.request

    # Set headers serialization info
    headers = cast(HeadersModel, request.headers).model_dump(context={"by_meta": "header"})

    # Base Headers are passed as extra args. we allow extra args for headers...
    assert {
        "accept": "application/json",
        "origin": Endpoints.HOME,
        "content-type": "application/json",
    }.items() <= headers.items(), "Base Headers do not match"

    # Login Cookie
    cookies = cast(CookiesModel, request.cookies).model_dump()
    assert {
        Jar.DSLANG: "US-EN",
        Jar.SITE: "USA",
    }.items() <= {k: v["value"] for k, v in cookies.items()}.items()

    # Login Body
    assert {
        "rememberMe": True,
        "accountName": AUTHENTICATED_USER,
        "trustTokens": [],
        "password": VALID_PASSWORD,
    }.items() <= cast(BodyModel, request.body).json_data.items(), "Login Body do not match"


async def test_login_success(user: Init):
    async with user as session:
        # We monkeypatch httpxclient to accept a json_data property. If predsent and not None,
        # it will be used as the json request body. If a json attribute is present, it will be used
        # instead of the json_data property

        session_mock = Mock()
        user._settings.token.events.session.connect(session_mock)

        # Fetch httpx pure response. This is the response object returned by the httpx client.
        # Set Headers
        response = await session.post(
            url=Endpoints.SIGIN,
            # Set Headers
            headers=user.dump_headers(),
            # Set Cookies
            cookies=user.dump_cookies(include=["dslang", "site"]),
            # Set params
            params={"isRememberMeEnabled": "true"},
            # Set Body
            json=user.dump_content(),
        )

        # Thre's a hook to httpx response to read response contents and store internally. But,
        # parsing response is only performance when response proerty on iLogin is called
        assert user._settings.token.session is None
        session_mock.assert_not_called()

        # HTTPX Response Status Code
        assert response.status_code == 200

        # HTTPX Response Headers
        assert {
            Header.REQUEST_ID: REQUEST_ID,
            Header.COUNTRY_CODE: "FRA",
            Header.SESSION_TOKEN: VALID_TOKEN,
        }.items() <= response.headers.items()

        # HTTPX Response Cookies Cookie
        assert {
            Jar.DSLANG: "US-EN",
            Jar.SITE: "USA",
            Jar.AASP: "login_aasp",
            Jar.ACN01: "acn01_value",
        }.items() <= dict(response.cookies).items()

    assert bool(user.response) is True
    assert user.response.headers.country_code == "FRA"
    assert user.response.headers.session_token == VALID_TOKEN

    # Settings is updated with the new session token when the context manager is exited
    assert user._settings.token.session == VALID_TOKEN
    session_mock.assert_called_once_with(VALID_TOKEN)


@pytest.fixture
def authenticated_2fa_user_settings():
    return Settings.model_validate(
        {
            "account": {
                "username": REQUIRES_2FA_USER,
                "password": VALID_PASSWORD,
            },
        },
    )


@pytest.fixture
@async_context(serialize_info={"settings": {"read": False}})
async def login_success(init_cookies, authenticated_2fa_user_settings, httpx_login_client):
    cookies, settings = (init_cookies, authenticated_2fa_user_settings)
    return Init(settings=settings, cookies=cookies, client=httpx_login_client)


async def test_login_2fa_user_success(login_success):
    async with login_success as session:
        # We monkeypatch httpxclient to accept a json_data property. If predsent and not None,
        # it will be used as the json request body. If a json attribute is present, it will be used
        # instead of the json_data property

        session_mock = Mock()
        login_success._settings.token.events.session.connect(session_mock)

        # Fetch httpx pure response. This is the response object returned by the httpx client.
        response = await session.send(login_success.request.model_dump_httpx_request())

        # Thre's a hook to httpx response to read response contents and store internally. But,
        # parsing response is only performance when response proerty on iLogin is called
        assert login_success._settings.token.session is None
        session_mock.assert_not_called()

        # HTTPX Response Status Code
        assert response.status_code == 409

        # HTTPX Response Headers
        assert {
            Header.REQUEST_ID: REQUEST_ID,
            Header.COUNTRY_CODE: "FRA",
            Header.SESSION_TOKEN: REQUIRES_2FA_TOKEN,
        }.items() <= response.headers.items()

        # HTTPX Response Cookies Cookie
        assert {
            Jar.DSLANG: "US-EN",
            Jar.SITE: "USA",
            Jar.AASP: "login_aasp",
            Jar.ACN01: "acn01_value",
        }.items() <= dict(response.cookies).items()

    assert bool(login_success.response) is True
    assert login_success.response.headers.country_code == "FRA"
    assert login_success.response.headers.session_token == REQUIRES_2FA_TOKEN

    # Settings is updated with the new session token when the context manager is exited
    assert login_success._settings.token.session == REQUIRES_2FA_TOKEN
    session_mock.assert_called_once_with(REQUIRES_2FA_TOKEN)


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


@pytest.fixture
@async_context(serialize_info={"settings": {"read": False}})
async def login_bad_credentials(init_cookies, authenticated_user_bad_password_settings, httpx_login_client):
    cookies, settings = init_cookies, authenticated_user_bad_password_settings
    return Init(settings=settings, cookies=cookies, client=httpx_login_client)


async def test_login_bad_credentials(login_bad_credentials):
    settings = login_bad_credentials._settings

    async with login_bad_credentials as session:
        # We monkeypatch httpxclient to accept a json_data property. If predsent and not None,
        # it will be used as the json request body. If a json attribute is present, it will be used
        # instead of the json_data property

        session_mock = Mock()
        settings.token.events.session.connect(session_mock)

        # Fetch httpx pure response. This is the response object returned by the httpx client.
        response = await session.send(login_bad_credentials.request.model_dump_httpx_request())

        # Thre's a hook to httpx response to read response contents and store internally. But,
        # parsing response is only performance when response proerty on iLogin is called
        assert settings.token.session is None
        session_mock.assert_not_called()

        # HTTPX Response Status Code
        assert response.status_code == 401

        # HTTPX Response Headers
        assert {
            Header.REQUEST_ID: REQUEST_ID,
        }.items() <= response.headers.items()

        # HTTPX Response Cookies Cookie
        assert {
            Jar.DSLANG: "US-EN",
            Jar.SITE: "USA",
            Jar.AASP: "login_aasp",
        }.items() <= response.cookies.items()

    assert bool(login_bad_credentials.response) is False
    assert login_bad_credentials.response.headers.country_code is None
    assert login_bad_credentials.response.headers.session_token is None

    # Settings is updated with the new session token when the context manager is exited
    assert len(login_bad_credentials.response.errors) == 1
    assert login_bad_credentials.response.errors[0].code == -20101
