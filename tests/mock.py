"""Library tests."""

from __future__ import annotations

import json
import re
from contextlib import contextmanager
from collections import OrderedDict
from typing import Callable

import httpx

from pyicloud.base import PyiCloud, PyiCloudSession
from pyicloud.constants import AppleHeaders as Header
from pyicloud.constants import Endpoints
from pyicloud.services import PyiCloudServices

from .const import (
    AUTHENTICATED_USER,
    REQUEST_ID,
    REQUIRES_2FA_TOKEN,
    REQUIRES_2FA_USER,
    VALID_2FA_CODE,
    VALID_COOKIE,
    VALID_PASSWORD,
    VALID_TOKEN,
    VALID_TOKENS,
    VALID_USERS,
)
from .const_account import ACCOUNT_DEVICES_WORKING, ACCOUNT_STORAGE_WORKING
from .const_account_family import ACCOUNT_FAMILY_WORKING
from .const_auth import (
    SESSION_RESPONSE_BODY_2FA,
    SESSION_RESPONSE_BODY_OK,
    SIGNIN_RESPONSE_BODY_2FA,
    TRUSTED_DEVICE_1,
    TRUSTED_DEVICES,
    VERIFICATION_CODE_KO,
    VERIFICATION_CODE_OK,
)
from .const_drive import (
    DRIVE_FILE_DOWNLOAD_WORKING,
    DRIVE_FOLDER_WORKING,
    DRIVE_ROOT_INVALID,
    DRIVE_ROOT_WORKING,
    DRIVE_SUBFOLDER_WORKING,
)
from .const_findmyiphone import FMI_FAMILY_WORKING


class ResponseMock(httpx.Response):
    """Mocked Response."""

    def __init__(self, result, status_code=200, **kwargs):
        """Set up response mock."""
        super().__init__(
            status_code,
            headers=kwargs.get("headers", {Header.REQUEST_ID: REQUEST_ID}),
            json=result,
        )
        self.result = result

    @property
    def text(self):
        """Return text."""
        return json.dumps(self.result)

    def json(self):
        """Return json."""
        return json.loads(self.text)


class PyiCloudSessionMock(PyiCloudSession):
    """Mocked PyiCloudSession."""

    def request(self, method, url, **kwargs):
        """Make the request."""
        params = kwargs.get("params") or {}
        headers = kwargs.get("headers") or {}  # httpx set headers to None if not present
        if "json" in kwargs and kwargs["data"] is None:
            # try to convert to json, if fails, it's already json
            try:
                kwargs["data"] = json.dumps(kwargs["json"])
            except json.JSONDecodeError:
                kwargs["data"] = kwargs["json"]
        data = json.loads(kwargs.get("data", "{}"))

        # Login
        if Endpoints.INIT in url:
            if "accountLogin" in url and method == "POST":
                if data.get("dsWebAuthToken") not in VALID_TOKENS:
                    self._error_callback(None, "Unknown reason")
                if data.get("dsWebAuthToken") == REQUIRES_2FA_TOKEN:
                    return ResponseMock(SESSION_RESPONSE_BODY_2FA)
                return ResponseMock(SESSION_RESPONSE_BODY_OK)

            if "listDevices" in url and method == "GET":
                return ResponseMock(TRUSTED_DEVICES)

            if "sendVerificationCode" in url and method == "POST":
                if data == TRUSTED_DEVICE_1:
                    return ResponseMock(VERIFICATION_CODE_OK)
                return ResponseMock(VERIFICATION_CODE_KO)

            if "validateVerificationCode" in url and method == "POST":
                TRUSTED_DEVICE_1.update({"verificationCode": "0", "trustBrowser": True})  # type: ignore
                if data == TRUSTED_DEVICE_1:
                    self._owner.user["apple_id"] = AUTHENTICATED_USER
                    return ResponseMock(VERIFICATION_CODE_OK)
                self._error_callback(None, "FOUND_CODE")

            if "validate" in url and method == "POST":
                if headers.get("X-APPLE-WEBAUTH-TOKEN") == VALID_COOKIE:
                    return ResponseMock(SESSION_RESPONSE_BODY_OK)
                self._error_callback(None, "Session expired")

        if Endpoints.AUTH in url:
            if "signin" in url and method == "POST":
                if data.get("accountName") not in VALID_USERS or data.get("password") != VALID_PASSWORD:
                    self._error_callback(None, "Unknown reason")
                if data.get("accountName") == REQUIRES_2FA_USER:
                    self._settings.token.session = REQUIRES_2FA_TOKEN
                    return ResponseMock(SIGNIN_RESPONSE_BODY_2FA, 409)

                self._settings.token.session = VALID_TOKEN
                return ResponseMock(SIGNIN_RESPONSE_BODY_2FA)

            if "securitycode" in url and method == "POST":
                if data.get("securityCode", {}).get("code") != VALID_2FA_CODE:
                    self._error_callback(None, "Incorrect code")

                self._settings.token.session = VALID_TOKEN
                return ResponseMock("", status_code=204)

            if "trust" in url and method == "GET":
                return ResponseMock("", status_code=204)

        # Account
        if "device/getDevices" in url and method == "GET":
            return ResponseMock(ACCOUNT_DEVICES_WORKING)
        if "family/getFamilyDetails" in url and method == "GET":
            return ResponseMock(ACCOUNT_FAMILY_WORKING)
        if "setup/ws/1/storageUsageInfo" in url and method == "GET":
            return ResponseMock(ACCOUNT_STORAGE_WORKING)

        # Drive
        if "retrieveItemDetailsInFolders" in url and method == "POST" and data[0].get("drivewsid"):
            if data[0].get("drivewsid") == "FOLDER::com.apple.CloudDocs::root":
                return ResponseMock(DRIVE_ROOT_WORKING)
            if data[0].get("drivewsid") == "FOLDER::com.apple.CloudDocs::documents":
                return ResponseMock(DRIVE_ROOT_INVALID)
            if data[0].get("drivewsid") == "FOLDER::com.apple.CloudDocs::1C7F1760-D940-480F-8C4F-005824A4E05B":
                return ResponseMock(DRIVE_FOLDER_WORKING)
            if data[0].get("drivewsid") == "FOLDER::com.apple.CloudDocs::D5AA0425-E84F-4501-AF5D-60F1D92648CF":
                return ResponseMock(DRIVE_SUBFOLDER_WORKING)

        # Drive download
        if "com.apple.CloudDocs/download/by_id" in url and method == "GET":
            if params.get("document_id") == "516C896C-6AA5-4A30-B30E-5502C2333DAE":
                return ResponseMock(DRIVE_FILE_DOWNLOAD_WORKING)
        if "icloud-content.com" in url and method == "GET":
            if "Scanned+document+1.pdf" in url:
                return ResponseMock({}, raw=open(".gitignore", "rb"))

        # Find My iPhone
        if "fmi" in url and method == "POST":
            return ResponseMock(FMI_FAMILY_WORKING)

        return None

    @contextmanager
    def stream(self, method, url, **kwargs):
        """Route stream calls through the local request mock to avoid network I/O."""
        response = self.request(method, url, **kwargs)
        assert response is not None, f"Unhandled request: {method} {url}"
        yield response


class PyiCloudTransportMock(httpx.MockTransport):
    username: str
    token: str

    def __init__(self) -> None:
        super().__init__(handler=self.handler)

    def _error_callback(self, request: httpx.Request | None, message: str) -> None:
        raise Exception(message)

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        method = request.method
        params = request.url.params
        headers = request.headers
        try:
            data = json.loads(request.content.decode("utf-8"))
        except json.JSONDecodeError:
            data = json.loads("{}")

        # Login
        if Endpoints.INIT in url:
            if "accountLogin" in url and method == "POST":
                if data.get("dsWebAuthToken") not in VALID_TOKENS:
                    self._error_callback(None, "Unknown reason")
                if data.get("dsWebAuthToken") == REQUIRES_2FA_TOKEN:
                    return ResponseMock(SESSION_RESPONSE_BODY_2FA)
                return ResponseMock(SESSION_RESPONSE_BODY_OK)

            if "listDevices" in url and method == "GET":
                return ResponseMock(TRUSTED_DEVICES)

            if "sendVerificationCode" in url and method == "POST":
                if data == TRUSTED_DEVICE_1:
                    return ResponseMock(VERIFICATION_CODE_OK)
                return ResponseMock(VERIFICATION_CODE_KO)

            if "validateVerificationCode" in url and method == "POST":
                TRUSTED_DEVICE_1.update({"verificationCode": "0", "trustBrowser": True})  # type: ignore
                if data == TRUSTED_DEVICE_1:
                    self.username = AUTHENTICATED_USER
                    return ResponseMock(VERIFICATION_CODE_OK)
                self._error_callback(None, "FOUND_CODE")

            if "validate" in url and method == "POST":
                if headers.get("X-APPLE-WEBAUTH-TOKEN") == VALID_COOKIE:
                    return ResponseMock(SESSION_RESPONSE_BODY_OK)
                self._error_callback(None, "Session expired")

        if Endpoints.AUTH in url:
            if "signin" in url and method == "POST":
                if data.get("accountName") not in VALID_USERS or data.get("password") != VALID_PASSWORD:
                    self._error_callback(None, "Unknown reason")
                if data.get("accountName") == REQUIRES_2FA_USER:
                    self.token = REQUIRES_2FA_TOKEN
                    return ResponseMock(SIGNIN_RESPONSE_BODY_2FA)

                self.token = VALID_TOKEN
                return ResponseMock(SIGNIN_RESPONSE_BODY_2FA)

            if "securitycode" in url and method == "POST":
                if data.get("securityCode", {}).get("code") != VALID_2FA_CODE:
                    self._error_callback(None, "Incorrect code")

                self.token = VALID_TOKEN
                return ResponseMock("", status_code=204)

            if "trust" in url and method == "GET":
                return ResponseMock("", status_code=204)

        # Account
        if "device/getDevices" in url and method == "GET":
            return ResponseMock(ACCOUNT_DEVICES_WORKING)
        if "family/getFamilyDetails" in url and method == "GET":
            return ResponseMock(ACCOUNT_FAMILY_WORKING)
        if "setup/ws/1/storageUsageInfo" in url and method == "GET":
            return ResponseMock(ACCOUNT_STORAGE_WORKING)

        # Drive
        if "retrieveItemDetailsInFolders" in url and method == "POST" and data[0].get("drivewsid"):
            if data[0].get("drivewsid") == "FOLDER::com.apple.CloudDocs::root":
                return ResponseMock(DRIVE_ROOT_WORKING)
            if data[0].get("drivewsid") == "FOLDER::com.apple.CloudDocs::documents":
                return ResponseMock(DRIVE_ROOT_INVALID)
            if data[0].get("drivewsid") == "FOLDER::com.apple.CloudDocs::1C7F1760-D940-480F-8C4F-005824A4E05B":
                return ResponseMock(DRIVE_FOLDER_WORKING)
            if data[0].get("drivewsid") == "FOLDER::com.apple.CloudDocs::D5AA0425-E84F-4501-AF5D-60F1D92648CF":
                return ResponseMock(DRIVE_SUBFOLDER_WORKING)

        # Drive download
        if "com.apple.CloudDocs/download/by_id" in url and method == "GET":
            if params.get("document_id") == "516C896C-6AA5-4A30-B30E-5502C2333DAE":
                return ResponseMock(DRIVE_FILE_DOWNLOAD_WORKING)
        if "icloud-content.com" in url and method == "GET":
            if "Scanned+document+1.pdf" in url:
                return ResponseMock({}, raw=open(".gitignore", "rb"))

        # Find My iPhone
        if "fmi" in url and method == "POST":
            return ResponseMock(FMI_FAMILY_WORKING)

        raise AssertionError(f"Unhandled request: {url}")


class PyiCloudMock(PyiCloud):
    """Mocked PyiCloudService."""

    session_cls = PyiCloudSessionMock

    def __init__(self, username: str, password: str | None = None):
        """Set up pyicloud service mock."""
        PyiCloud.__init__(self, username, password)


class PyiCloudServicesMock(PyiCloudServices):
    """Mocked PyiCloudService."""

    def __init__(self, endpoint):
        """Set up pyicloud service mock."""
        PyiCloudServices.__init__(self, endpoint)


class PyiCloudMockTransport(httpx.MockTransport):
    def __init__(
        self, *, routes: list[tuple[str | re.Pattern, Callable[[httpx.Request], httpx.Response]]] | None = None
    ):
        self.routes = OrderedDict()
        if routes is not None:
            for route, handler in routes:
                self.add_route(route=route, handler=handler)

        super().__init__(handler=self.handler)

    def add_route(self, *, route: str | re.Pattern, handler: Callable[[httpx.Request], httpx.Response]) -> None:
        self.routes[route] = handler

    def handler(self, request: httpx.Request) -> httpx.Response:
        for route, handler in self.routes.items():
            if isinstance(route, re.Pattern) and route.match(str(request.url)):
                return handler(request)
            if isinstance(route, str) and str(request.url).startswith(route):
                return handler(request)
        # Not found
        return httpx.Response(404)
