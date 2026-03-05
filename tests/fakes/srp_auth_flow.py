from __future__ import annotations

import base64
import hashlib
import json

import httpx
import srp
import srp._pysrp as srp_impl

from pyicloud.constants import AppleHeaders as Header
from pyicloud.constants import Endpoints
from tests.const import (
    AUTH_ATTRIBUTES,
    AUTHENTICATED_USER,
    REQUEST_ID,
    REQUIRES_2FA_TOKEN,
    REQUIRES_2FA_USER,
    SCNT,
    SESSION_ID,
    VALID_2FA_CODE,
    VALID_PASSWORD,
    VALID_TOKEN,
)
from tests.const_account_family import APPLE_ID_COUNTRY_CODE
from tests.const_auth import (
    ACCOUNT_LOGIN_RESPONSE_COOKIES_OK,
    SECURITY_CODE_RESPONSE_BODY_KO_BAD_SECURITY_CODE,
    SECURITY_CODE_RESPONSE_COOKIES_KO,
    SECURITY_CODE_RESPONSE_COOKIES_OK,
    SECURITY_CODE_RESPONSE_HEADERS_KO,
    SECURITY_CODE_RESPONSE_HEADERS_OK,
    SIGNIN_REQUEST_COOKIES,
    SIGNIN_RESPONSE_2FA_COOKIES,
    SIGNIN_RESPONSE_BODY_2FA,
    SIGNIN_RESPONSE_BODY_KO_BAD_PASSWORD,
    SIGNIN_RESPONSE_KO_COOKIES,
    SIGNIN_RESPONSE_OK_COOKIES,
    TRUST_RESPONSE_OK_COOKIES,
    TRUST_RESPONSE_HEADERS_OK,
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


class SrpAuthFlowFake:
    def __init__(self, *, requires_2fa: bool = False) -> None:
        self.requires_2fa = requires_2fa
        self._challenges: dict[str, tuple[object, str]] = {}
        self._security_verified = False

    @staticmethod
    def _build_response(*, status: int, headers: dict[str, str], cookies, content):
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

    def _handle_signin_init(self, request: httpx.Request) -> httpx.Response:
        data = json.loads(request.content)
        username = data.get("accountName")
        if username not in {AUTHENTICATED_USER, REQUIRES_2FA_USER} or "a" not in data:
            return self._error_response()

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

    def _handle_signin_complete(self, request: httpx.Request) -> httpx.Response:
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

        if self.requires_2fa or username == REQUIRES_2FA_USER:
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

    def _handle_security_code(self, request: httpx.Request) -> httpx.Response:
        data = json.loads(request.content)
        if data.get("securityCode", {}).get("code") != VALID_2FA_CODE:
            return self._build_response(
                status=400,
                headers=SECURITY_CODE_RESPONSE_HEADERS_KO,
                cookies=SECURITY_CODE_RESPONSE_COOKIES_KO,
                content=SECURITY_CODE_RESPONSE_BODY_KO_BAD_SECURITY_CODE,
            )

        self._security_verified = True
        return self._build_response(
            status=204,
            headers=SECURITY_CODE_RESPONSE_HEADERS_OK,
            cookies=SECURITY_CODE_RESPONSE_COOKIES_OK,
            content=b"",
        )

    def _handle_trust(self, request: httpx.Request) -> httpx.Response:
        if self.requires_2fa and not self._security_verified:
            return self._error_response()
        return self._build_response(
            status=204,
            headers=TRUST_RESPONSE_HEADERS_OK,
            cookies=TRUST_RESPONSE_OK_COOKIES,
            content=b"",
        )

    def _handle_account_login(self, request: httpx.Request) -> httpx.Response:
        data = json.loads(request.content)
        token = data.get("dsWebAuthToken")
        if token not in {VALID_TOKEN, REQUIRES_2FA_TOKEN}:
            return self._build_response(
                status=400,
                headers={Header.REQUEST_ID: REQUEST_ID, Header.SCNT: SCNT},
                cookies=[],
                content={"service_errors": [{"code": "-20528", "message": "Invalid session."}]},
            )

        return self._build_response(
            status=200,
            headers={Header.REQUEST_ID: REQUEST_ID, Header.SCNT: SCNT},
            cookies=ACCOUNT_LOGIN_RESPONSE_COOKIES_OK,
            content={"webservices": {"findme": {"status": "active", "url": "https://example.test"}}},
        )

    def _handle_validate(self, request: httpx.Request) -> httpx.Response:
        return self._build_response(
            status=200,
            headers={Header.REQUEST_ID: REQUEST_ID, Header.SCNT: SCNT},
            cookies=ACCOUNT_LOGIN_RESPONSE_COOKIES_OK,
            content={"webservices": {"findme": {"status": "active", "url": "https://example.test"}}},
        )

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if request.method == "POST" and url.startswith(Endpoints.SIGNIN_INIT):
            return self._handle_signin_init(request)
        if request.method == "POST" and url.startswith(Endpoints.SIGNIN_COMPLETE):
            return self._handle_signin_complete(request)
        if request.method == "POST" and url.startswith(Endpoints.SECURITY_CODE):
            return self._handle_security_code(request)
        if request.method == "GET" and url.startswith(Endpoints.TRUST):
            return self._handle_trust(request)
        if request.method == "POST" and url.startswith(Endpoints.ACCOUNT_LOGIN):
            return self._handle_account_login(request)
        if request.method == "POST" and url.startswith(Endpoints.VALIDATE):
            return self._handle_validate(request)
        raise AssertionError(f"Unhandled request: {request.method} {request.url}")
