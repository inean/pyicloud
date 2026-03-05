import base64
import hashlib
import json
from typing import cast
from unittest.mock import Mock, patch

import httpx
import pytest
import srp
import srp._pysrp as srp_impl

from pyicloud.constants import AppleCookies as Jar
from pyicloud.constants import AppleHeaders as Header
from pyicloud.constants import Endpoints
from pyicloud.models.cookies import Cookies
from pyicloud.models.settings import Settings
from pyicloud.sessions import BodyModel, CookiesModel, HeadersModel
from pyicloud.sessions.signin import SignIn, SignInRequest
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
from tests.const_account_family import APPLE_ID_COUNTRY_CODE
from tests.const_auth import (
    SIGNIN_REQUEST_COOKIES,
    SIGNIN_RESPONSE_2FA_COOKIES,
    SIGNIN_RESPONSE_BODY_2FA,
    SIGNIN_RESPONSE_BODY_KO_BAD_PASSWORD,
    SIGNIN_RESPONSE_KO_COOKIES,
    SIGNIN_RESPONSE_OK_COOKIES,
)


class _SrpPassword:
    def __init__(self, password: str):
        self.password = password
        self.salt: bytes | None = None
        self.iterations: int | None = None
        self.key_length = 32

    def set_encrypt_info(self, *, salt: bytes, iterations: int, key_length: int = 32) -> None:
        self.salt = salt
        self.iterations = iterations
        self.key_length = key_length

    def encode(self) -> bytes:
        if self.salt is None or self.iterations is None:
            raise ValueError("SRP salt/iterations are not initialized")
        password_hash = hashlib.sha256(self.password.encode("utf-8")).digest()
        return hashlib.pbkdf2_hmac("sha256", password_hash, self.salt, self.iterations, self.key_length)


class SignInSrpMock:
    def __init__(
        self,
        *,
        fail_init: bool = False,
        malformed_init: bool = False,
        fail_complete: bool = False,
    ) -> None:
        self._challenges: dict[str, tuple[object, str]] = {}
        self.fail_init = fail_init
        self.malformed_init = malformed_init
        self.fail_complete = fail_complete
        self.init_requests: list[httpx.Request] = []
        self.complete_requests: list[httpx.Request] = []

    def _build_response(self, *, status: int, headers: dict[str, str], cookies, content):
        header_items = list(headers.items()) + [cookie.items() for cookie in cookies]
        return httpx.Response(status_code=status, headers=header_items, json=content if content else None)

    def _error_response(self):
        return self._build_response(
            status=401,
            headers={
                Header.REQUEST_ID: REQUEST_ID,
                Header.SCNT: SCNT,
            },
            cookies=SIGNIN_RESPONSE_KO_COOKIES,
            content=SIGNIN_RESPONSE_BODY_KO_BAD_PASSWORD,
        )

    def _handle_init(self, request: httpx.Request) -> httpx.Response:
        self.init_requests.append(request)
        if self.fail_init:
            return self._error_response()
        data = json.loads(request.content)
        username = data.get("accountName")
        if username not in VALID_USERS or "a" not in data:
            return self._error_response()

        if self.malformed_init:
            return self._build_response(
                status=200,
                headers={
                    Header.REQUEST_ID: REQUEST_ID,
                    Header.SCNT: SCNT,
                    Header.SESSION_ID: SESSION_ID,
                },
                cookies=SIGNIN_REQUEST_COOKIES,
                content={"iteration": "invalid-iteration", "salt": "%%%"},
            )

        salt = b"mock_srp_salt_16"
        iterations = 10_000
        srp.rfc5054_enable()
        srp.no_username_in_x()

        srp_password = _SrpPassword(VALID_PASSWORD)
        srp_password.set_encrypt_info(salt=salt, iterations=iterations, key_length=32)

        client_public = base64.b64decode(data["a"])
        N, g = srp_impl.get_ng(srp.NG_2048, None, None)
        x = srp_impl.gen_x(hashlib.sha256, salt, username, srp_password)
        verifier_key = srp_impl.long_to_bytes(pow(g, x, N))
        verifier = srp.Verifier(username, salt, verifier_key, client_public, hash_alg=srp.SHA256, ng_type=srp.NG_2048)
        _, server_public = verifier.get_challenge()
        assert server_public is not None

        challenge = f"mock-{len(self._challenges) + 1}"
        self._challenges[challenge] = (verifier, username)

        return self._build_response(
            status=200,
            headers={
                Header.REQUEST_ID: REQUEST_ID,
                Header.SCNT: SCNT,
                Header.SESSION_ID: SESSION_ID,
            },
            cookies=SIGNIN_REQUEST_COOKIES,
            content={
                "iteration": iterations,
                "salt": base64.b64encode(salt).decode(),
                "protocol": "s2k",
                "b": base64.b64encode(server_public).decode(),
                "c": challenge,
            },
        )

    def _handle_complete(self, request: httpx.Request) -> httpx.Response:
        self.complete_requests.append(request)
        if self.fail_complete:
            return self._error_response()
        data = json.loads(request.content)
        challenge = data.get("c")
        if challenge not in self._challenges:
            return self._error_response()

        verifier, username = self._challenges.pop(challenge)
        client_m1 = base64.b64decode(data.get("m1", ""))
        expected_hamk = verifier.verify_session(client_m1)
        if not expected_hamk:
            return self._error_response()

        client_m2 = base64.b64decode(data.get("m2", ""))
        if client_m2 != expected_hamk:
            return self._error_response()

        headers = {
            Header.AUTH_ATTRIBUTES: AUTH_ATTRIBUTES,
            Header.COUNTRY_CODE: APPLE_ID_COUNTRY_CODE,
            Header.REQUEST_ID: REQUEST_ID,
            Header.SCNT: SCNT,
            Header.SESSION_ID: SESSION_ID,
        }

        if username == REQUIRES_2FA_USER:
            headers[Header.SESSION_TOKEN] = REQUIRES_2FA_TOKEN
            headers[Header.TRUST_TOKEN_ELIGIBLE] = "true"
            return self._build_response(
                status=409,
                headers=headers,
                cookies=SIGNIN_RESPONSE_2FA_COOKIES,
                content=SIGNIN_RESPONSE_BODY_2FA,
            )

        headers[Header.SESSION_TOKEN] = VALID_TOKEN
        return self._build_response(
            status=200,
            headers=headers,
            cookies=SIGNIN_RESPONSE_OK_COOKIES,
            content={},
        )

    def handler(self, request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        if str(request.url).startswith(Endpoints.SIGNIN_INIT):
            return self._handle_init(request)
        if str(request.url).startswith(Endpoints.SIGNIN_COMPLETE):
            return self._handle_complete(request)
        raise AssertionError(f"Unhandled request: {request.method} {request.url}")


_SIGNIN_SRP_MOCK = SignInSrpMock()


def signin_handler(request: httpx.Request) -> httpx.Response:
    """Compatibility handler used by kkza.py mock transport wiring."""
    return _SIGNIN_SRP_MOCK.handler(request)


@pytest.fixture
def signin_mock() -> SignInSrpMock:
    return SignInSrpMock()


@pytest.fixture
def signin_client(signin_mock: SignInSrpMock) -> httpx.AsyncClient:
    transport = httpx.MockTransport(signin_mock.handler)
    return httpx.AsyncClient(transport=transport)


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


@pytest.fixture
def signin_session_state_settings():
    with patch("locale.getlocale", return_value=["en_US", "UTF-8"]):
        return Settings.model_validate(
            {
                "account": {
                    "username": AUTHENTICATED_USER,
                    "password": VALID_PASSWORD,
                    "session_id": SESSION_ID,
                },
                "client_settings": {
                    "scnt": SCNT,
                },
                "token": {
                    "trust": VALID_TOKEN,
                },
            },
        )


@pytest.fixture
def signin_cookies():
    return Cookies.model_validate([cookie._content for cookie in SIGNIN_REQUEST_COOKIES])


@pytest.fixture
def user(signin_cookies, signin_settings, signin_client):
    return SignIn(
        settings=signin_settings,
        cookies=signin_cookies,
        client=signin_client,
    )


@pytest.fixture
def user_secure(signin_cookies, signin_secure_settings, signin_client):
    return SignIn(
        settings=signin_secure_settings,
        cookies=signin_cookies,
        client=signin_client,
    )


@pytest.fixture
def user_bad_credentials(signin_cookies, signin_bad_credentials_settings, signin_client):
    return SignIn(
        settings=signin_bad_credentials_settings,
        cookies=signin_cookies,
        client=signin_client,
    )


@pytest.fixture
def user_with_session_state(signin_cookies, signin_session_state_settings, signin_client):
    return SignIn(
        settings=signin_session_state_settings,
        cookies=signin_cookies,
        client=signin_client,
    )


def test_request_classes(signin_settings, signin_cookies):
    user = SignIn(settings=signin_settings, cookies=signin_cookies)
    assert isinstance(user, SignIn)

    assert isinstance(user.request, SignInRequest)


@pytest.fixture
def mock():
    return Mock()


async def test_events(user: SignIn, mock: Mock):
    user._settings.token.events.session.connect(mock)
    assert cast(SignIn, user)._settings.token.session is None
    mock.assert_not_called()

    async with user as session:
        assert cast(SignIn, user)._settings.token.session is None
        mock.assert_not_called()
        await user.send_signin(session)
        assert user._settings.token.session is None
        mock.assert_not_called()

    assert user._settings.token.session is not None
    mock.assert_called_once()


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
    assert expected_base_headers.items() <= headers.items(), "Base headers do not match"
    assert expected_oauth_headers.items() <= headers.items(), "OAuth headers do not match"


async def test_signin_request_from_models_headers(user: SignIn, expected_base_headers, expected_oauth_headers):
    headers = cast(HeadersModel, user.request.headers).model_dump(context={"by_meta": "header"})
    assert expected_base_headers.items() <= headers.items(), "Base headers do not match"
    assert expected_oauth_headers.items() <= headers.items(), "OAuth headers do not match"


@pytest.fixture
def expected_cookies():
    return {
        Jar.DSLANG: "US-EN",
        Jar.SITE: "USA",
    }


async def test_signin_request_cookies(user: SignIn, expected_cookies):
    with patch("locale.getlocale", return_value="en_US"):
        assert expected_cookies.items() <= user.dump_cookies(include=["dslang", "site"]).items()


async def test_signin_request_from_models_cookies(user: SignIn, expected_cookies):
    cookies = cast(CookiesModel, user.request.cookies).model_dump()
    assert expected_cookies.items() <= {k: v["value"] for k, v in cookies.items()}.items()


@pytest.fixture
def expected_body():
    return {
        "rememberMe": True,
        "accountName": AUTHENTICATED_USER,
        "trustTokens": [],
    }


async def test_signin_request_body(user: SignIn, expected_body: dict):
    assert expected_body.items() <= cast(dict, user.dump_content()).items(), "Body does not match"


async def test_signin_request_from_models_body(user: SignIn, expected_body: dict):
    assert expected_body.items() <= cast(BodyModel, user.request.body).json_data.items(), "Body does not match"


@pytest.fixture
def response_factory():
    async def _response(signin_user: SignIn):
        async with signin_user as session:
            await signin_user.send_signin(session)
        return signin_user.response

    return _response


@pytest.mark.parametrize(
    "signin_user, code",
    [
        ("user", 200),
        ("user_secure", 409),
        ("user_bad_credentials", 401),
    ],
)
async def test_signin_response_status_code(signin_user, code, response_factory, request):
    user = request.getfixturevalue(signin_user)
    response = await response_factory(user)
    assert response.status_code == code


async def test_signin_response_user(user: SignIn):
    async with user as session:
        await user.send_signin(session)

    assert bool(user.response) is True
    assert user.response.headers.country_code == APPLE_ID_COUNTRY_CODE
    assert user.response.headers.session_token == VALID_TOKEN
    assert user._settings.token.session == VALID_TOKEN
    assert user._settings.client_settings.trust_eligible is None


async def test_signin_response_user_secure(user_secure: SignIn):
    async with user_secure as session:
        await user_secure.send_signin(session)

    assert bool(user_secure.response) is True
    assert user_secure.response.headers.country_code == APPLE_ID_COUNTRY_CODE
    assert user_secure.response.headers.session_token == REQUIRES_2FA_TOKEN
    assert user_secure._settings.token.session == REQUIRES_2FA_TOKEN
    assert user_secure._settings.client_settings.trust_eligible is True


async def test_signin_bad_credentials(user_bad_credentials: SignIn):
    async with user_bad_credentials as session:
        await user_bad_credentials.send_signin(session)

    assert bool(user_bad_credentials.response) is False
    assert user_bad_credentials.response.headers.country_code is None
    assert user_bad_credentials.response.headers.session_token is None
    assert len(user_bad_credentials.response.errors) == 1
    assert user_bad_credentials.response.errors[0].code == -20101


async def test_signin_missing_password_raises_value_error(signin_cookies: Cookies):
    with patch("locale.getlocale", return_value=["en_US", "UTF-8"]):
        settings = Settings.model_validate(
            {
                "account": {
                    "username": AUTHENTICATED_USER,
                    "password": None,
                },
            },
        )
    user = SignIn(settings=settings, cookies=signin_cookies)
    with pytest.raises(ValueError, match="Password is required for SRP signin flow."):
        async with user as session:
            await user.send_signin(session)


async def test_signin_init_error_skips_complete(
    signin_settings: Settings,
    signin_cookies: Cookies,
):
    mock = SignInSrpMock(fail_init=True)
    user = SignIn(
        settings=signin_settings,
        cookies=signin_cookies,
        client=httpx.AsyncClient(transport=httpx.MockTransport(mock.handler)),
    )

    async with user as session:
        await user.send_signin(session)

    assert len(mock.init_requests) == 1
    assert len(mock.complete_requests) == 0


async def test_signin_invalid_init_response_raises_value_error(
    signin_settings: Settings,
    signin_cookies: Cookies,
):
    mock = SignInSrpMock(malformed_init=True)
    user = SignIn(
        settings=signin_settings,
        cookies=signin_cookies,
        client=httpx.AsyncClient(transport=httpx.MockTransport(mock.handler)),
    )

    with pytest.raises(ValueError, match="Invalid SRP init response."):
        async with user as session:
            await user.send_signin(session)

    assert len(mock.init_requests) == 1
    assert len(mock.complete_requests) == 0


async def test_signin_complete_error_is_exposed(
    signin_settings: Settings,
    signin_cookies: Cookies,
):
    mock = SignInSrpMock(fail_complete=True)
    user = SignIn(
        settings=signin_settings,
        cookies=signin_cookies,
        client=httpx.AsyncClient(transport=httpx.MockTransport(mock.handler)),
    )

    async with user as session:
        await user.send_signin(session)

    assert bool(user.response) is False
    assert user.response.status_code == 401
    assert len(mock.init_requests) == 1
    assert len(mock.complete_requests) == 1


async def test_signin_complete_request_propagates_trust_token_and_request_id(
    user_with_session_state: SignIn,
    signin_mock: SignInSrpMock,
):
    async with user_with_session_state as session:
        await user_with_session_state.send_signin(session)

    assert len(signin_mock.complete_requests) == 1
    complete_request = signin_mock.complete_requests[0]
    complete_payload = json.loads(complete_request.content)
    assert complete_payload["trustTokens"] == [VALID_TOKEN]
    assert complete_request.headers[Header.REQUEST_ID] == REQUEST_ID


async def test_signin_init_request_propagates_scnt_and_session_id(
    user_with_session_state: SignIn,
    signin_mock: SignInSrpMock,
):
    async with user_with_session_state as session:
        await user_with_session_state.send_signin(session)

    assert len(signin_mock.init_requests) == 1
    init_headers = signin_mock.init_requests[0].headers
    assert init_headers[Header.SCNT] == SCNT
    assert init_headers[Header.SESSION_ID] == SESSION_ID
