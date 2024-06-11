from __future__ import annotations

import json
from typing import TYPE_CHECKING, cast, get_args, overload
from unittest.mock import Mock, patch

import httpx
import pytest
from pytest_lazy_fixtures import lf

from pyicloud.constants import AppleCookies as Jar
from pyicloud.constants import AppleHeaders as Header
from pyicloud.constants import Endpoints
from pyicloud.models.cookies import Cookies
from pyicloud.models.settings import Settings
from pyicloud.sessions import BodyModel, CookiesModel, HeadersModel
from pyicloud.sessions.account_login import (
    AccountLogin,
    AccountLoginRequest,
    AccountLoginResponse,
    AccountLoginResponseCookies,
    AccountLoginServiceRequest,
)
from pyicloud.utils import mapping
from tests import process_cookies
from tests.const import (
    AUTHENTICATED_USER,
    INVALID_TOKEN,
    ONE_FACTOR_SERVICE,
    REQUIRES_2FA_TOKEN,
    SCNT,
    SESSION_ID,
    VALID_PASSWORD,
    VALID_TOKEN,
    VALID_TOKENS,
    VALID_USERS,
)
from tests.const_auth import (
    ACCOUNT_LOGIN_REQUEST_COOKIES,
    ACCOUNT_LOGIN_REQUEST_HEADERS,
    ACCOUNT_LOGIN_RESPONSE_BODY_2FA,
    ACCOUNT_LOGIN_RESPONSE_BODY_KO_INVALID_SESSION_TOKEN,
    ACCOUNT_LOGIN_RESPONSE_BODY_KO_MISSING_APPLE_ID,
    ACCOUNT_LOGIN_RESPONSE_BODY_OK,
    ACCOUNT_LOGIN_RESPONSE_COOKIES_KO,
    ACCOUNT_LOGIN_RESPONSE_COOKIES_OK,
    ACCOUNT_LOGIN_RESPONSE_HEADERS_KO,
    ACCOUNT_LOGIN_RESPONSE_HEADERS_OK,
    DES_COOKIE,
)

if TYPE_CHECKING:

    class Request(httpx.Request):
        cookies: dict[str, str]
else:
    Request = httpx.Request


@overload
def account_login_handler(request: httpx.Request) -> httpx.Response: ...


@overload
def account_login_handler(request: Request) -> httpx.Response: ...


@process_cookies
def account_login_handler(request: Request | httpx.Request) -> httpx.Response:
    assert request.method == "POST"
    assert str(request.url).startswith(Endpoints.ACCOUNT_LOGIN)

    status_code = 500  # Internal error
    while True:
        # Malformed request
        if not mapping.compare(dict(ACCOUNT_LOGIN_REQUEST_HEADERS), dict(request.headers)):
            content = b""
            break
        if not mapping.compare(
            dict(map(tuple, ACCOUNT_LOGIN_REQUEST_COOKIES)),
            cast(Request, request).cookies,
            ignore={DES_COOKIE.name},
        ):
            content = b""
            break

        # Success path
        status_code = 200
        headers = ACCOUNT_LOGIN_RESPONSE_HEADERS_OK
        cookies = ACCOUNT_LOGIN_RESPONSE_COOKIES_OK
        data = json.loads(request.content)

        if "dsWebAuthToken" in data:
            if data["dsWebAuthToken"] == REQUIRES_2FA_TOKEN and data.get("trustToken") in VALID_TOKENS:
                content = ACCOUNT_LOGIN_RESPONSE_BODY_2FA
                break
            if data["dsWebAuthToken"] in VALID_TOKENS:
                content = ACCOUNT_LOGIN_RESPONSE_BODY_OK
                break

            # Error Path
            status_code = 400
            headers = ACCOUNT_LOGIN_RESPONSE_HEADERS_KO
            cookies = ACCOUNT_LOGIN_RESPONSE_COOKIES_KO
            content = ACCOUNT_LOGIN_RESPONSE_BODY_KO_INVALID_SESSION_TOKEN
            break

        if data.get("apple_id") in VALID_USERS and data.get("password") == VALID_PASSWORD:
            content = ACCOUNT_LOGIN_RESPONSE_BODY_OK
            break

        # Error Path
        status_code = 400
        headers = ACCOUNT_LOGIN_RESPONSE_HEADERS_KO
        cookies = ACCOUNT_LOGIN_RESPONSE_COOKIES_KO
        content = ACCOUNT_LOGIN_RESPONSE_BODY_KO_MISSING_APPLE_ID
        break

    # If status_code is 500, test will fail
    assert status_code != 500
    headers = list(headers.items()) + list(map(lambda o: o.items(), cookies))
    return httpx.Response(headers=headers, status_code=status_code, json=content if content else None)


@pytest.fixture
def account_login_client() -> httpx.AsyncClient:
    matchers = {
        "url": Endpoints.ACCOUNT_LOGIN,
        "method": "POST",
    }
    return httpx.AsyncClient(mounts={matchers["url"]: httpx.MockTransport(account_login_handler)})


##
# Settings Fixture
##
@pytest.fixture
def account_login_settings():
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
def account_login_invalid_token_settings():
    with patch("locale.getlocale", return_value=["en_US", "UTF-8"]):
        return Settings.model_validate(
            {
                "account": {
                    "username": AUTHENTICATED_USER,
                    "session_id": SESSION_ID,
                },
                "token": {
                    "session": INVALID_TOKEN,
                },
                "client_settings": {
                    "scnt": SCNT,
                },
            },
        )


@pytest.fixture
def account_login_one_factor_settings():
    with patch("locale.getlocale", return_value=["en_US", "UTF-8"]):
        return Settings.model_validate(
            {
                "account": {
                    "username": AUTHENTICATED_USER,
                    "password": VALID_PASSWORD,
                },
                "client_settings": {
                    "scnt": SCNT,
                },
            },
        )


##
# Cookies Fixture
##
@pytest.fixture
def account_login_cookies():
    return Cookies.model_validate([cookie.content for cookie in ACCOUNT_LOGIN_REQUEST_COOKIES])


##
# User Fixtures
##
@pytest.fixture
def account_login_user(account_login_cookies, account_login_settings, account_login_client):
    return AccountLogin(
        settings=account_login_settings,
        cookies=account_login_cookies,
        client=account_login_client,
    )


@pytest.fixture
async def account_login_invalid_token(
    account_login_cookies, account_login_invalid_token_settings, account_login_client
):
    return AccountLogin(
        settings=account_login_invalid_token_settings,
        cookies=account_login_cookies,
        client=account_login_client,
    )


@pytest.fixture
async def account_login_service(account_login_cookies, account_login_one_factor_settings, account_login_client):
    return AccountLogin(
        settings=account_login_one_factor_settings,
        cookies=account_login_cookies,
        data={"service": ONE_FACTOR_SERVICE},
        client=account_login_client,
    )


###
# General Tests
##
@pytest.mark.parametrize(
    "user, request_cls",
    [
        (lf("account_login_user"), AccountLoginRequest),
        (lf("account_login_service"), AccountLoginServiceRequest),
    ],
)
def test_request_classes(user, request_cls):
    assert user.request_cls == request_cls
    assert user.request_cls in get_args(get_args(AccountLogin.__orig_bases__[0])[0])  # type: ignore
    assert user.response_cls == AccountLoginResponse
    assert user.response_cls in get_args(AccountLogin.__orig_bases__[0])  # type: ignore


##
# Request Tests
##
@pytest.fixture
def expected_base_headers():
    return {
        "accept": "application/json",
        "origin": Endpoints.HOME,
    }


@pytest.fixture
def expected_oauth_headers(account_login_user):
    return {
        "x-apple-oauth-client-id": "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d",
        "x-apple-oauth-client-type": "firstPartyAuth",
        "x-apple-oauth-redirect-uri": Endpoints.HOME,
        "x-apple-oauth-require-grant-code": "true",
        "x-apple-oauth-response-type": "code",
        "x-apple-oauth-response-mode": "web_message",
        "x-apple-oauth-state": account_login_user._settings.client_settings.client_id,
        "x-apple-widget-key": "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d",
    }


@pytest.fixture
def expected_account_login_headers():
    return {
        Header.SESSION_ID: SESSION_ID,
        Header.SCNT: SCNT,
    }


async def test_account_login_request_headers(
    account_login_user: AccountLogin,
    expected_base_headers,
    expected_oauth_headers,
    expected_account_login_headers,
):
    headers = account_login_user.dump_headers()
    # Base Headers
    assert expected_base_headers.items() <= headers.items(), "Base Headers do not match"
    # Oauth Headers
    assert expected_oauth_headers.items() <= headers.items(), "Login Headers do not match"
    # AccountLogin Headers
    assert expected_account_login_headers.items() <= headers.items(), "AccountLogin Headers do not match"


async def test_account_login_request_from_models_headers(
    account_login_user: AccountLogin,
    expected_base_headers,
    expected_oauth_headers,
    expected_account_login_headers,
):
    # Set headers serialization info
    headers = cast(HeadersModel, account_login_user.request.headers).model_dump(context={"by_meta": "header"})
    # Base Headers are passed as extra args. we allow extra args for headers...
    assert expected_base_headers.items() <= headers.items(), "Base Headers do not match"
    # Oauth Headers
    assert expected_oauth_headers.items() <= headers.items(), "Login Headers do not match"
    # AccountLogin Headers
    assert expected_account_login_headers.items() <= headers.items(), "AccountLogin Headers do not match"


@pytest.fixture
def expected_cookies():
    return {
        Jar.DSLANG: "US-EN",
        Jar.SITE: "USA",
        DES_COOKIE.name: DES_COOKIE.value,
    }


async def test_account_login_request_cookies(account_login_user: AccountLogin, expected_cookies):
    # Login Cookies
    with patch("locale.getlocale", return_value="en_US"):
        assert expected_cookies.items() <= account_login_user.dump_cookies(include=expected_cookies.keys()).items()


async def test_account_login_request_from_models_cookies(account_login_user: AccountLogin, expected_cookies):
    cookies = cast(CookiesModel, account_login_user.request.cookies).model_dump()
    assert expected_cookies.items() <= {v["key"]: v["value"] for k, v in cookies.items()}.items()


# Define a fixture for the expected body
@pytest.fixture
def expected_token_body():
    return {
        "extended_login": True,
        "dsWebAuthToken": VALID_TOKEN,
        "trustToken": VALID_TOKEN,
    }


@pytest.fixture
def expected_service_body():
    return {
        "apple_id": AUTHENTICATED_USER,
        "password": VALID_PASSWORD,
        "service": ONE_FACTOR_SERVICE,
    }


@pytest.mark.parametrize(
    "user, expected_body",
    [
        (lf("account_login_user"), lf("expected_token_body")),
        (lf("account_login_service"), lf("expected_service_body")),
    ],
)
async def test_account_login_request_body(user: AccountLogin, expected_body: dict):
    assert expected_body.items() <= cast(dict, user.dump_content()).items(), "Body do not match"


@pytest.mark.parametrize(
    "user, expected_body",
    [
        (lf("account_login_user"), lf("expected_token_body")),
        (lf("account_login_service"), lf("expected_service_body")),
    ],
)
async def test_account_login_request_from_models_body(user: AccountLogin, expected_body: dict):
    assert expected_body.items() <= cast(BodyModel, user.request.body).json_data.items()


##
# Response Tests
##
@pytest.fixture
def mock():
    return Mock()


@pytest.fixture
async def response_factory(expected_cookies):
    async def _response(user: AccountLogin):
        async with user as session:
            response = await session.post(
                url=Endpoints.ACCOUNT_LOGIN,
                headers=user.dump_headers(),
                cookies=user.dump_cookies(include=expected_cookies.keys()),
                json=user.dump_content(),
            )
            return response

    return _response


@pytest.mark.parametrize(
    "user, code",
    [
        (lf("account_login_user"), 200),  # type: ignore
        (lf("account_login_invalid_token"), 400),  #  type: ignore
    ],
)
async def test_account_login_response_status_code(user, code, response_factory):
    response = await response_factory(user)
    assert response.status_code == code


@pytest.mark.parametrize(
    "user, headers",
    [
        (lf("account_login_user"), ACCOUNT_LOGIN_RESPONSE_HEADERS_OK),
        (lf("account_login_invalid_token"), ACCOUNT_LOGIN_RESPONSE_HEADERS_KO),
    ],
)
async def test_account_login_response_headers(user, headers, response_factory):
    response = await response_factory(user)
    assert headers.items() <= response.headers.items()


@pytest.mark.parametrize(
    "user, cookies",
    [
        (lf("account_login_user"), dict(map(tuple, ACCOUNT_LOGIN_RESPONSE_COOKIES_OK))),
        (lf("account_login_invalid_token"), dict(map(tuple, ACCOUNT_LOGIN_RESPONSE_COOKIES_KO))),
    ],
)
async def test_account_login_response_cookies(user, cookies, response_factory):
    response = await response_factory(user)
    assert cookies.items() <= dict(response.cookies).items()


async def test_account_login_response_user(account_login_user: AccountLogin):
    async with account_login_user as session:
        _ = await session.send(account_login_user.request.model_dump_httpx_request())

    assert bool(account_login_user.response) is True
    assert cast(AccountLoginResponseCookies, account_login_user.response.cookies).webauth_hsa_trust
    assert account_login_user._settings.token.trust == VALID_TOKEN


async def test_account_login_invalid_token(account_login_invalid_token: AccountLogin):
    async with account_login_invalid_token as session:
        # Fetch httpx pure response. This is the response object returned by the httpx client.
        _ = await session.send(account_login_invalid_token.request.model_dump_httpx_request())

    assert bool(account_login_invalid_token.response) is False

    # Settings is updated with the new session token when the context manager is exited
    assert len(account_login_invalid_token.response.errors) == 1
    assert account_login_invalid_token.response.errors[0].code == 0
    assert (
        account_login_invalid_token.response.errors[0].message
        == ACCOUNT_LOGIN_RESPONSE_BODY_KO_INVALID_SESSION_TOKEN["error"]
    )
