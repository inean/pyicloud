"""HTTPX related stuff"""

from __future__ import annotations

import httpx

from collections import namedtuple

from .config import PyiCloudFileConfig as Config
from .log import PyiCloudPasswordFilter, get_logger


class iConstants:
    AUTH_ENDPOINT = "https://idmsa.apple.com/appleauth/auth"
    HOME_ENDPOINT = "https://www.icloud.com"
    SETUP_ENDPOINT = "https://setup.icloud.com/setup/ws/1"


Response = namedtuple("Response", ["result", "err"])


class iBaseSession:
    HEADER_DATA = {
        "X-Apple-ID-Account-Country": "auth.accountCountryCode",
        "X-Apple-ID-Session-Id": "clientSettings.xAppleIDSessionId",
        "X-Apple-Session-Token": "auth.token",
        "X-Apple-TwoSV-Trust-Token": "auth.xAppleTwosvTrustToken",
        "scnt": "clientSettings.scnt",
    }

    def __init__(self, config: Config, client: httpx.Client | None = None):
        self._config = config
        self._httpx = client or httpx.Client(follow_redirects=True)

        # Store last response
        self._response: httpx.Response | None = None
        self._httpx.event_hooks["request"].append(lambda value: setattr(self, "_response", value))

        # set password filter
        PyiCloudPasswordFilter.register(self, logger=get_logger("http"))

    async def __aenter__(self):
        # Load session and cookies
        self._config.load()
        # Set headers
        self._httpx.headers.update(
            {
                "Origin": iConstants.HOME_ENDPOINT,
                "Referer": "%s/" % iConstants.HOME_ENDPOINT,
            }
        )
        return self._httpx

    async def __aexit__(self, exc_type, exc, tb):
        if self._response:
            # Update session config
            for header, key in self.HEADER_DATA.items():
                if header in self._response.headers:
                    self._config.update({key: self._response.headers[header]})
        # Store session and cookies
        self._config.save()
        await self._httpx.close()


class iSignIn(iBaseSession):
    ENDPOINT = "https://idmsa.apple.com/appleauth/auth/signin"

    async def __aenter__(self):
        retval = await super().__aenter__()

        # Prepare Headers for POST Request
        headers = {
            "Accept": "*/*",
            "Content-Type": "application/json",
            "X-Apple-OAuth-Client-Id": "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d",
            "X-Apple-OAuth-Client-Type": "firstPartyAuth",
            "X-Apple-OAuth-Redirect-URI": iConstants.HOME_ENDPOINT,
            "X-Apple-OAuth-Require-Grant-Code": "true",
            "X-Apple-OAuth-Response-Type": "code",
            "X-Apple-OAuth-Response-Mode": "web_message",
            "X-Apple-OAuth-State": self._config["clientId"],
            "X-Apple-Widget-Key": "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d",
        }
        if scnt := self._config.get("clientSettings.scnt"):
            headers["scnt"] = scnt
        if ssid := self._config.get("clientSettings.xAppleIDSessionId"):
            headers["X-Apple-ID-Session-Id"] = ssid
        # Set headers
        self._httpx.headers.update(headers)

        # Set params
        self._httpx.params = {"isRememberMeEnabled": "true"}
        # Set body
        self._httpx.json = {
            "rememberMe": True,
            "accountName": self._config["username"],
            "password": self._config.get("password", ""),
            "trustTokens": [*[self._config.get("auth.xAppleTwosvTrustToken", [])]],
        }

        return retval

    async def __aexit__(self, exc_type, exc, tb):
        # If no Status 200 OK response, Clean up cookies
        return await super().__aexit__(exc_type, exc, tb)
