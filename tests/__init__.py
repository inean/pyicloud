"""Library tests."""

from __future__ import annotations

import json

import httpx

from pyicloud import base
from pyicloud.base import iConstants

from .const import (
    AUTHENTICATED_USER,
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
from .const_drive import (
    DRIVE_FILE_DOWNLOAD_WORKING,
    DRIVE_FOLDER_WORKING,
    DRIVE_ROOT_INVALID,
    DRIVE_ROOT_WORKING,
    DRIVE_SUBFOLDER_WORKING,
)
from .const_findmyiphone import FMI_FAMILY_WORKING
from .const_login import (
    AUTH_OK,
    LOGIN_2FA,
    LOGIN_WORKING,
    TRUSTED_DEVICE_1,
    TRUSTED_DEVICES,
    VERIFICATION_CODE_KO,
    VERIFICATION_CODE_OK,
)


class ResponseMock(httpx.Response):
    """Mocked Response."""

    def __init__(self, result, status_code=200, **kwargs):
        """Set up response mock."""
        super().__init__(status_code)
        self.result = result
        self.status_code = status_code
        self.raw = kwargs.get("raw")
        self.headers = kwargs.get("headers", {})

    @property
    def text(self):
        """Return text."""
        return json.dumps(self.result)

    def json(self):
        """Return json."""
        return json.loads(self.text)


class PyiCloudSessionMock(base.PyiCloudSession):
    """Mocked PyiCloudSession."""

    def request(self, method, url, **kwargs):
        """Make the request."""
        params = kwargs.get("params")
        headers = kwargs.get("headers")
        data = json.loads(kwargs.get("data", "{}"))

        # Login
        if iConstants.SETUP_ENDPOINT in url:
            if "accountLogin" in url and method == "POST":
                if data.get("dsWebAuthToken") not in VALID_TOKENS:
                    self._error_callback(None, "Unknown reason")
                if data.get("dsWebAuthToken") == REQUIRES_2FA_TOKEN:
                    return ResponseMock(LOGIN_2FA)
                return ResponseMock(LOGIN_WORKING)

            if "listDevices" in url and method == "GET":
                return ResponseMock(TRUSTED_DEVICES)

            if "sendVerificationCode" in url and method == "POST":
                if data == TRUSTED_DEVICE_1:
                    return ResponseMock(VERIFICATION_CODE_OK)
                return ResponseMock(VERIFICATION_CODE_KO)

            if "validateVerificationCode" in url and method == "POST":
                TRUSTED_DEVICE_1.update({"verificationCode": "0", "trustBrowser": True})
                if data == TRUSTED_DEVICE_1:
                    self._owner.user["apple_id"] = AUTHENTICATED_USER
                    return ResponseMock(VERIFICATION_CODE_OK)
                self._error_callback(None, "FOUND_CODE")

            if "validate" in url and method == "POST":
                if headers.get("X-APPLE-WEBAUTH-TOKEN") == VALID_COOKIE:
                    return ResponseMock(LOGIN_WORKING)
                self._error_callback(None, "Session expired")

        if iConstants.AUTH_ENDPOINT in url:
            if "signin" in url and method == "POST":
                if data.get("accountName") not in VALID_USERS or data.get("password") != VALID_PASSWORD:
                    self._error_callback(None, "Unknown reason")
                if data.get("accountName") == REQUIRES_2FA_USER:
                    self._config["auth"]["token"] = REQUIRES_2FA_TOKEN
                    return ResponseMock(AUTH_OK)

                self._config["auth"]["token"] = VALID_TOKEN
                return ResponseMock(AUTH_OK)

            if "securitycode" in url and method == "POST":
                if data.get("securityCode", {}).get("code") != VALID_2FA_CODE:
                    self._error_callback(None, "Incorrect code")

                self._config["auth"]["token"] = VALID_TOKEN
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


class PyiCloudMock(base.PyiCloud):
    """Mocked PyiCloudService."""

    def __init__(
        self,
        username,
        password,
    ):
        """Set up pyicloud service mock."""
        base.PyiCloudSession = PyiCloudSessionMock
        base.PyiCloud.__init__(self, username, password)


class PyiCloudServicesMock(base.PyiCloudServices):
    """Mocked PyiCloudService."""

    def __init__(
        self,
        endpoint,
    ):
        """Set up pyicloud service mock."""
        base.PyiCloudServices.__init__(self, endpoint)
