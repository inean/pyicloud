import json
from typing import cast, get_args
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
from pyicloud.sessions.signin import SignIn, SignInRequest, SignInResponse
from tests.const import (
    AUTH_ATTRIBUTES,
    AUTHENTICATED_USER,
    INVALID_PASSWORD,
    REQUEST_ID,
    REQUIRES_2FA_TOKEN,
    REQUIRES_2FA_USER,
    SCNT,
    SESSION_ID,
    VALID_PASSWORD,
    VALID_TOKEN,
    VALID_USERS,
)
from tests.const_account_family import (
    APPLE_ID_COUNTRY_CODE,
)

from .const_auth import (
    ACCOUNT_LOGIN_RESPONSE_BODY_OK,
    SIGNIN_REQUEST_COOKIES,
    SIGNIN_RESPONSE_2FA_COOKIES,
    SIGNIN_RESPONSE_BODY_2FA,
    SIGNIN_RESPONSE_BODY_KO_BAD_PASSWORD,
    SIGNIN_RESPONSE_KO_COOKIES,
    SIGNIN_RESPONSE_OK_COOKIES,
)


def signin_handler(request: httpx.Request) -> httpx.Response:
    assert request.method == "POST"
    assert str(request.url).startswith(Endpoints.SIGNIN)

    status_code = 500  # Internal error
    headers = {Header.REQUEST_ID: REQUEST_ID, Header.SCNT: SCNT}

    # Success path
    data = json.loads(request.content)
    if data.get("accountName") in VALID_USERS and data.get("password") == VALID_PASSWORD:
        status_code = 200
        headers.update(
            {
                Header.SESSION_TOKEN: VALID_TOKEN,
                Header.COUNTRY_CODE: APPLE_ID_COUNTRY_CODE,
                Header.SESSION_ID: SESSION_ID,
                Header.AUTH_ATTRIBUTES: AUTH_ATTRIBUTES,
            }
        )
        cookies = SIGNIN_RESPONSE_OK_COOKIES
        content = ACCOUNT_LOGIN_RESPONSE_BODY_OK
        # 2FA path
        if data.get("accountName") == REQUIRES_2FA_USER:
            status_code = 409
            headers.update(
                {
                    Header.SESSION_TOKEN: REQUIRES_2FA_TOKEN,
                    Header.TRUST_TOKEN_ELIGIBLE: "true",
                }
            )
            cookies = SIGNIN_RESPONSE_2FA_COOKIES
            content = SIGNIN_RESPONSE_BODY_2FA
    # Error Path
    else:
        status_code = 401
        cookies = SIGNIN_RESPONSE_KO_COOKIES
        content = SIGNIN_RESPONSE_BODY_KO_BAD_PASSWORD

    # If status_code is 500, test will fail
    assert status_code != 500
    headers = list(headers.items()) + list(map(lambda o: o.items(), cookies))
    return httpx.Response(headers=headers, status_code=status_code, json=content if content else None)


@pytest.fixture
def signin_client() -> httpx.AsyncClient:
    matchers = {
        "url": Endpoints.SIGNIN,
        "method": "POST",
    }
    return httpx.AsyncClient(mounts={matchers["url"]: httpx.MockTransport(signin_handler)})


##
# Settings Fixture
##
@pytest.fixture
def signin_settings():
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
def signin_secure_settings():
    with patch("locale.getlocale", return_value=["en_US", "UTF-8"]):
        return Settings.model_validate(
            {
                "account": {
                    "username": REQUIRES_2FA_USER,
                    "password": VALID_PASSWORD,
                },
            },
        )


@pytest.fixture
def signin_bad_credentials_settings():
    with patch("locale.getlocale", return_value=["en_US", "UTF-8"]):
        return Settings.model_validate(
            {
                "account": {
                    "username": AUTHENTICATED_USER,
                    "password": INVALID_PASSWORD,
                },
            },
        )


##
# Cookies Fixture
##
@pytest.fixture
def signin_cookies():
    return Cookies.model_validate([cookie._content for cookie in SIGNIN_REQUEST_COOKIES])


##
# User Fixtures
##


@pytest.fixture
def user(signin_cookies, signin_settings, signin_client):
    return SignIn(
        settings=signin_settings,
        cookies=signin_cookies,
        client=signin_client,
    )


@pytest.fixture
async def user_secure(signin_cookies, signin_secure_settings, signin_client):
    return SignIn(
        settings=signin_secure_settings,
        cookies=signin_cookies,
        client=signin_client,
    )


@pytest.fixture
async def user_bad_credentials(signin_cookies, signin_bad_credentials_settings, signin_client):
    return SignIn(
        settings=signin_bad_credentials_settings,
        cookies=signin_cookies,
        client=signin_client,
    )


###
# General Tests
##
def test_request_classes(signin_settings, signin_cookies):
    user = SignIn(settings=signin_settings, cookies=signin_cookies)
    assert isinstance(user, SignIn)

    assert user.request_cls == SignInRequest
    assert user.request_cls in get_args(SignIn.__orig_bases__[0])  # type: ignore
    assert user.response_cls == SignInResponse
    assert user.request_cls in get_args(SignIn.__orig_bases__[0])  # type: ignore


@pytest.mark.parametrize("user", ["user", "user_without_cookies"], indirect=True)
async def test_events(user: SignIn, mock: Mock):
    user._settings.token.events.session.connect(mock)
    # assert signin_user._settings.token.session is None
    assert cast(SignIn, user)._settings.token.session is None
    mock.assert_not_called()
    async with user as session:
        # Pre call.
        assert cast(SignIn, user)._settings.token.session is None
        mock.assert_not_called()
        await session.send(user.request.model_dump_httpx_request())
        # Post call
        assert user._settings.token.session is None
        mock.assert_not_called()
    # Settings are only updated after the context manager is exited
    assert user._settings.token.session is not None
    mock.assert_called_once()


##
# Request Tests
##
@pytest.fixture
def expected_base_headers():
    return {
        "accept": "application/json",
        "origin": Endpoints.HOME,
        "content-type": "application/json",
    }


@pytest.fixture
def expected_oauth_headers(user):
    return {
        "content-type": "application/json",
        "x-apple-oauth-client-id": "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d",
        "x-apple-oauth-client-type": "firstPartyAuth",
        "x-apple-oauth-redirect-uri": Endpoints.HOME,
        "x-apple-oauth-require-grant-code": "true",
        "x-apple-oauth-response-type": "code",
        "x-apple-oauth-response-mode": "web_message",
        "x-apple-oauth-state": user._settings.client_settings.client_id,
        "x-apple-widget-key": "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d",
    }


async def test_signin_request_headers(user: SignIn, expected_base_headers, expected_oauth_headers):
    headers = user.dump_headers()
    # Base Headers
    assert expected_base_headers.items() <= headers.items(), "Base Headers do not match"
    # Oauth Headers
    assert expected_oauth_headers.items() <= headers.items(), "Login Headers do not match"


async def test_signin_request_from_models_headers(user: SignIn, expected_base_headers, expected_oauth_headers):
    # Set headers serialization info
    headers = cast(HeadersModel, user.request.headers).model_dump(context={"by_meta": "header"})
    # Base Headers are passed as extra args. we allow extra args for headers...
    assert expected_base_headers.items() <= headers.items(), "Base Headers do not match"
    # Oauth Headers
    assert expected_oauth_headers.items() <= headers.items(), "Login Headers do not match"


@pytest.fixture
def expected_cookies():
    return {
        Jar.DSLANG: "US-EN",
        Jar.SITE: "USA",
    }


async def test_signin_request_cookies(user: SignIn, expected_cookies):
    # Login Cookies
    with patch("locale.getlocale", return_value="en_US"):
        assert expected_cookies.items() <= user.dump_cookies(include=["dslang", "site"]).items()


async def test_signin_request_from_models_cookies(user: SignIn, expected_cookies):
    # Login Cookie
    cookies = cast(CookiesModel, user.request.cookies).model_dump()
    assert expected_cookies.items() <= {k: v["value"] for k, v in cookies.items()}.items()


# Define a fixture for the expected body
@pytest.fixture
def expected_body():
    return {
        "rememberMe": True,
        "accountName": AUTHENTICATED_USER,
        "trustTokens": [],
        "password": VALID_PASSWORD,
    }


async def test_signin_request_body(user: SignIn, expected_body: dict):
    assert expected_body.items() <= cast(dict, user.dump_content()).items(), "Login Body do not match"


async def test_signin_request_from_models_body(user: SignIn, expected_body: dict):
    assert expected_body.items() <= cast(BodyModel, user.request.body).json_data.items(), "Login Body do not match"


##
# Response Tests
##
@pytest.fixture
def mock():
    return Mock()


@pytest.fixture
async def response_factory():
    async def _response(user: SignIn):
        async with user as session:
            response = await session.post(
                url=Endpoints.SIGNIN,
                headers=user.dump_headers(),
                cookies=user.dump_cookies(include=["dslang", "site"]),
                params={"isRememberMeEnabled": "true"},
                json=user.dump_content(),
            )
            return response

    return _response


@pytest.mark.parametrize(
    "signin_user, code",
    [
        (lf("user"), 200),
        (lf("user_secure"), 409),
        (lf("user_bad_credentials"), 401),
    ],
)
async def test_signin_response_status_code(signin_user, code, response_factory):
    response = await response_factory(signin_user)
    assert response.status_code == code


@pytest.mark.parametrize(
    "signin_user, headers",
    [
        (
            lf("user"),  # type: ignore
            {
                Header.AUTH_ATTRIBUTES: AUTH_ATTRIBUTES,
                Header.COUNTRY_CODE: APPLE_ID_COUNTRY_CODE,
                Header.REQUEST_ID: REQUEST_ID,
                Header.SCNT: SCNT,
                Header.SESSION_ID: SESSION_ID,
                Header.SESSION_TOKEN: VALID_TOKEN,
            },
        ),
        (
            lf("user_secure"),  # type: ignore
            {
                Header.REQUEST_ID: REQUEST_ID,
                Header.SCNT: SCNT,
                Header.SESSION_TOKEN: REQUIRES_2FA_TOKEN,
                Header.TRUST_TOKEN_ELIGIBLE: "true",
            },
        ),  # type: ignore
        (
            lf("user_bad_credentials"),  #  type: ignore
            {
                Header.REQUEST_ID: REQUEST_ID,
                Header.SCNT: SCNT,
            },
        ),
    ],
)
async def test_signin_response_headers(signin_user, headers, response_factory):
    response = await response_factory(signin_user)
    assert headers.items() <= response.headers.items()


@pytest.mark.parametrize(
    "signin_user, cookies",
    [
        (
            lf("user"),
            {
                Jar.DSLANG: "US-EN",
                Jar.SITE: "USA",
            },
        ),
        (
            lf("user_secure"),
            {
                Jar.DSLANG: "US-EN",
                Jar.SITE: "USA",
                Jar.AASP: "login_aasp",
                Jar.ACN01: "acn01_value",
            },
        ),
        (
            lf("user_bad_credentials"),
            {
                Jar.DSLANG: "US-EN",
                Jar.SITE: "USA",
                Jar.AASP: "login_aasp",
            },
        ),
    ],
)
async def test_signin_response_cookies(signin_user, cookies, response_factory):
    response = await response_factory(signin_user)
    assert cookies.items() <= dict(response.cookies).items()


async def test_signin_response_user(user: SignIn):
    async with user as session:
        _ = await session.send(user.request.model_dump_httpx_request())

    assert bool(user.response) is True
    assert user.response.headers.country_code == APPLE_ID_COUNTRY_CODE
    assert user.response.headers.session_token == VALID_TOKEN

    # Settings is updated with the new session token when the context manager is exited
    assert user._settings.token.session == VALID_TOKEN
    assert user._settings.client_settings.trust_eligible is None


async def test_signin_response_user_secure(user_secure: SignIn):
    async with user_secure as session:
        _ = await session.send(user_secure.request.model_dump_httpx_request())

    assert bool(user_secure.response) is True
    assert user_secure.response.headers.country_code == APPLE_ID_COUNTRY_CODE
    assert user_secure.response.headers.session_token == REQUIRES_2FA_TOKEN

    # Settings is updated with the new session token when the context manager is exited
    assert user_secure._settings.token.session == REQUIRES_2FA_TOKEN
    assert user_secure._settings.client_settings.trust_eligible is True


async def test_signin_bad_credentials(user_bad_credentials: SignIn):
    async with user_bad_credentials as session:
        # Fetch httpx pure response. This is the response object returned by the httpx client.
        _ = await session.send(user_bad_credentials.request.model_dump_httpx_request())

    assert bool(user_bad_credentials.response) is False
    assert user_bad_credentials.response.headers.country_code is None
    assert user_bad_credentials.response.headers.session_token is None

    # Settings is updated with the new session token when the context manager is exited
    assert len(user_bad_credentials.response.errors) == 1
    assert user_bad_credentials.response.errors[0].code == -20101
