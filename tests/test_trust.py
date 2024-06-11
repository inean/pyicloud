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
from pyicloud.sessions.trust import Trust, TrustRequest, TrustResponse
from pyicloud.utils import mapping
from tests import process_cookies
from tests.const import (
    AUTH_ATTRIBUTES,
    AUTHENTICATED_USER,
    INVALID_SESSION_ID,
    INVALID_TOKEN,
    REQUEST_ID,
    SCNT,
    SESSION_ID,
    VALID_TOKEN,
)
from tests.const_account_family import APPLE_ID_COUNTRY_CODE

from .const_auth import (
    DES_COOKIE,
    TRUST_REQUEST_COOKIES,
    TRUST_REQUEST_HEADERS,
    TRUST_RESPONSE_BODY_KO_INVALID_SESSION,
    TRUST_RESPONSE_HEADERS_KO,
    TRUST_RESPONSE_HEADERS_OK,
    TRUST_RESPONSE_KO_COOKIES,
    TRUST_RESPONSE_OK_COOKIES,
)

if TYPE_CHECKING:

    class Request(httpx.Request):
        cookies: dict[str, str]
else:
    Request = httpx.Request


@overload
def trust_handler(request: httpx.Request) -> httpx.Response: ...


@overload
def trust_handler(request: Request) -> httpx.Response: ...


@process_cookies
def trust_handler(request: httpx.Request) -> httpx.Response:
    assert request.method == "GET"
    assert request.content == b""
    assert str(request.url).startswith(Endpoints.TRUST)

    status_code = 500  # Internal error

    while True:
        # Malformed request
        if not mapping.compare(TRUST_REQUEST_HEADERS, dict(request.headers), exclude_values=True):
            break
        if not mapping.compare(
            dict(map(tuple, TRUST_REQUEST_COOKIES)),
            cast(Request, request).cookies,
            ignore={DES_COOKIE.name},
        ):
            break

        # Success path
        if request.headers[Header.SESSION_ID] == SESSION_ID:
            status_code = 204
            headers = TRUST_RESPONSE_HEADERS_OK
            cookies = TRUST_RESPONSE_OK_COOKIES
            content = b""
            break

        # Error Path
        status_code = 400
        headers = TRUST_RESPONSE_HEADERS_KO
        cookies = TRUST_RESPONSE_KO_COOKIES
        content = TRUST_RESPONSE_BODY_KO_INVALID_SESSION
        break

    # If status_code is 500, test will fail
    assert status_code != 500
    headers = list(headers.items()) + list(map(lambda o: o.items(), cookies))
    return httpx.Response(headers=headers, status_code=status_code, json=content if content else None)


@pytest.fixture
def trust_client() -> httpx.AsyncClient:
    matchers = {
        "url": Endpoints.SIGNIN,
        "method": "GET",
    }
    return httpx.AsyncClient(mounts={matchers["url"]: httpx.MockTransport(trust_handler)})


##
# Settings Fixture
##
@pytest.fixture
def trust_settings():
    with patch("locale.getlocale", return_value=["en_US", "UTF-8"]):
        return Settings.model_validate(
            {
                "account": {
                    "username": AUTHENTICATED_USER,
                    "session_id": SESSION_ID,
                },
                "token": {
                    "session": VALID_TOKEN,
                },
                "client_settings": {
                    "scnt": SCNT,
                },
            },
        )


@pytest.fixture
def trust_invalid_token_settings():
    return Settings.model_validate(
        {
            "account": {
                "username": AUTHENTICATED_USER,
                "session_id": INVALID_SESSION_ID,
            },
            "token": {
                "session": INVALID_TOKEN,
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
def trust_cookies():
    return Cookies.model_validate([cookie._content for cookie in TRUST_REQUEST_COOKIES])


##
# User Fixtures
##


@pytest.fixture
def user(trust_cookies, trust_settings, trust_client):
    return Trust(
        settings=trust_settings,
        cookies=trust_cookies,
        client=trust_client,
    )


@pytest.fixture
async def user_invalid_token(trust_cookies, trust_invalid_token_settings, trust_client):
    return Trust(
        settings=trust_invalid_token_settings,
        cookies=trust_cookies,
        client=trust_client,
    )


###
# General Tests
##
def test_request_classes(trust_settings, trust_cookies):
    user = Trust(settings=trust_settings, cookies=trust_cookies)
    assert isinstance(user, Trust)

    assert user.request_cls == TrustRequest
    assert user.request_cls in get_args(Trust.__orig_bases__[0])  # type: ignore
    assert user.response_cls == TrustResponse
    assert user.request_cls in get_args(Trust.__orig_bases__[0])  # type: ignore


@pytest.mark.parametrize("user", ["user", "user_without_cookies"], indirect=True)
async def test_events(user: Trust, mock: Mock):
    user._settings.token.events.trust.connect(mock)
    # assert trust_user._settings.token.session is None
    assert cast(Trust, user)._settings.token.trust is None
    mock.assert_not_called()
    async with user as session:
        # Pre call.
        assert cast(Trust, user)._settings.token.trust is None
        mock.assert_not_called()
        await session.send(user.request.model_dump_httpx_request())
        # Post call
        assert user._settings.token.trust is None
        mock.assert_not_called()
    # Settings are only updated after the context manager is exited
    assert user._settings.token.trust is not None
    mock.assert_called_once()


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
def expected_oauth_headers(user):
    return {
        "x-apple-oauth-client-id": "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d",
        "x-apple-oauth-client-type": "firstPartyAuth",
        "x-apple-oauth-redirect-uri": Endpoints.HOME,
        "x-apple-oauth-require-grant-code": "true",
        "x-apple-oauth-response-type": "code",
        "x-apple-oauth-response-mode": "web_message",
        "x-apple-oauth-state": user._settings.client_settings.client_id,
        "x-apple-widget-key": "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d",
    }


@pytest.fixture
def expected_trust_headers():
    return {
        Header.SESSION_ID: SESSION_ID,
        Header.SCNT: SCNT,
    }


async def test_trust_request_headers(
    user: Trust,
    expected_base_headers,
    expected_oauth_headers,
    expected_trust_headers,
):
    headers = user.dump_headers()
    # Base Headers
    assert expected_base_headers.items() <= headers.items(), "Base Headers do not match"
    # Oauth Headers
    assert expected_oauth_headers.items() <= headers.items(), "Login Headers do not match"
    # Trust Headers
    assert expected_trust_headers.items() <= headers.items(), "Trust Headers do not match"


async def test_trust_request_from_models_headers(
    user: Trust,
    expected_base_headers,
    expected_oauth_headers,
    expected_trust_headers,
):
    # Set headers serialization info
    headers = cast(HeadersModel, user.request.headers).model_dump(context={"by_meta": "header"})
    # Base Headers are passed as extra args. we allow extra args for headers...
    assert expected_base_headers.items() <= headers.items(), "Base Headers do not match"
    # Oauth Headers
    assert expected_oauth_headers.items() <= headers.items(), "Login Headers do not match"
    # Trust Headers
    assert expected_trust_headers.items() <= headers.items(), "Trust Headers do not match"


@pytest.fixture
def expected_cookies():
    return {
        Jar.DSLANG: "US-EN",
        Jar.SITE: "USA",
        Jar.AASP: "login_aasp",
        Jar.ACN01: "acn01_value",
    }


async def test_trust_request_cookies(user: Trust, expected_cookies):
    # Login Cookies
    with patch("locale.getlocale", return_value="en_US"):
        assert expected_cookies.items() <= user.dump_cookies(include=expected_cookies.keys()).items()


async def test_trust_request_from_models_cookies(user: Trust, expected_cookies):
    # Login Cookie
    cookies = cast(CookiesModel, user.request.cookies).model_dump()
    assert expected_cookies.items() <= {k: v["value"] for k, v in cookies.items()}.items()


async def test_trust_request_body(user: Trust):
    assert user.dump_content() == b"", "Login Body do not match"


async def test_trust_request_from_models_body(user: Trust):
    assert cast(BodyModel, user.request.body).json_data is None
    assert cast(BodyModel, user.request.body).content == b""


##
# Response Tests
##
@pytest.fixture
def mock():
    return Mock()


@pytest.fixture
async def response_factory(expected_cookies):
    async def _response(user: Trust):
        async with user as session:
            response = await session.get(
                url=Endpoints.TRUST,
                headers=user.dump_headers(),
                cookies=user.dump_cookies(include=expected_cookies.keys()),
            )
            return response

    return _response


@pytest.mark.parametrize(
    "trust_user, code",
    [
        (lf("user"), 204),  # type: ignore
        (lf("user_invalid_token"), 400),  #  type: ignore
    ],
)
async def test_trust_response_status_code(trust_user, code, response_factory):
    response = await response_factory(trust_user)
    assert response.status_code == code


@pytest.mark.parametrize(
    "trust_user, headers",
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
                Header.TRUST_TOKEN: VALID_TOKEN,
            },
        ),
        (
            lf("user_invalid_token"),  #  type: ignore
            {
                Header.REQUEST_ID: REQUEST_ID,
                Header.SCNT: SCNT,
            },
        ),
    ],
)
async def test_trust_response_headers(trust_user, headers, response_factory):
    response = await response_factory(trust_user)
    assert headers.items() <= response.headers.items()


@pytest.mark.parametrize(
    "trust_user, cookies",
    [
        (
            lf("user"),  # type: ignore
            {
                Jar.DSLANG: "US-EN",
                Jar.SITE: "USA",
                DES_COOKIE.name: DES_COOKIE.value,
            },
        ),  # type: ignore
        (
            lf("user_invalid_token"),  #  type: ignore
            {
                Jar.DSLANG: "US-EN",
                Jar.SITE: "USA",
            },
        ),
    ],
)
async def test_trust_response_cookies(trust_user, cookies, response_factory):
    response = await response_factory(trust_user)
    assert cookies.items() <= dict(response.cookies).items()


async def test_trust_response_user(user: Trust):
    async with user as session:
        _ = await session.send(user.request.model_dump_httpx_request())

    assert bool(user.response) is True
    assert user.response.cookies.des is not None
    assert user.response.cookies.des.key == DES_COOKIE.name
    assert user.response.cookies.des.value == DES_COOKIE.value
    assert user.response.headers.trust_token == VALID_TOKEN

    # Settings is updated with the new session token when the context manager is exited
    assert DES_COOKIE.name in user._cookies
    assert user._settings.token.trust == VALID_TOKEN


async def test_trust_invalid_token(user_invalid_token: Trust):
    async with user_invalid_token as session:
        # Fetch httpx pure response. This is the response object returned by the httpx client.
        _ = await session.send(user_invalid_token.request.model_dump_httpx_request())

    assert bool(user_invalid_token.response) is False
    assert user_invalid_token.response.cookies.des is None
    assert user_invalid_token.response.headers.trust_token is None

    # Settings is updated with the new session token when the context manager is exited
    assert len(user_invalid_token.response.errors) == 1
    assert user_invalid_token.response.errors[0].code == -20528
