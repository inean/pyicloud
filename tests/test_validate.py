from __future__ import annotations

from typing import TYPE_CHECKING, cast, overload

import httpx

from pyicloud.constants import AppleCookies as Jar
from pyicloud.constants import Endpoints
from pyicloud.utils import mapping
from tests import process_cookies
from tests.const import (
    VALID_TOKEN,
)
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
