"""HTTPX related stuff"""

from __future__ import annotations

import httpx

from typing import Dict
from dataclasses import dataclass, field, fields
from functools import WRAPPER_ASSIGNMENTS

from .config import PyiCloudFileConfig as Config
from .log import PyiCloudPasswordFilter, get_logger


def configure(cls=None, *, read: bool = True, write: bool = True):
    """Load and store session and cookies when entering and exiting the context manager."""

    if cls is None:
        # Return the actual decorator
        return lambda cls: configure(cls, read=read, write=write)

    class Wrapper(cls):
        """New wrapper that will extend the wrapper `cls` to make it look like `wrapped`"""

        async def __aenter__(self):
            # Load session and cookies
            read and self._config.load()
            return await super().__aenter__()

        async def __aexit__(self, exc_type, exc, tb):
            await super().__aexit__(exc_type, exc, tb)
            # Store session and cookies
            write and self._config.save()

    # Assign the attributes
    for attr in WRAPPER_ASSIGNMENTS:
        setattr(Wrapper, attr, getattr(cls, attr))

    if not isinstance(cls, type):
        raise TypeError("cls must be a class")
    return Wrapper


def allow_from(*accepted_verbs):
    """Allow the given methods to be called without a valid session."""

    def decorator(cls):
        class Wrapper(cls):
            """New wrapper that will extend the wrapper `cls` to make it look like `wrapped`"""

            class ProxyWrapper:
                __slots__ = ["_httpx"]

                def __init__(self, httpx):
                    self._httpx = httpx

                def __getattr__(self, name):
                    VERBS = ["get", "post", "put", "delete", "options", "head", "patch"]
                    if name in VERBS and name not in accepted_verbs:
                        raise NameError(f"Verb {name} is not allowed")
                    return getattr(self._httpx, name)

            for attr in WRAPPER_ASSIGNMENTS:
                setattr(ProxyWrapper, attr, getattr(httpx.AsyncClient, attr))

            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self._httpx = Wrapper.ProxyWrapper(self._httpx)

        # Assign the attributes
        for attr in WRAPPER_ASSIGNMENTS:
            setattr(Wrapper, attr, getattr(cls, attr))
        return Wrapper

    return decorator


class iConstants:
    AUTH_ENDPOINT = "https://idmsa.apple.com/appleauth/auth"
    HOME_ENDPOINT = "https://www.icloud.com"
    SETUP_ENDPOINT = "https://setup.icloud.com/setup/ws/1"


@dataclass
class iResponse:
    """Response data."""

    err: iError | None = None
    result: iResult | None = None

    def __bool__(self):
        """Return True if the response is successful."""
        return not bool(self.err)

    @classmethod
    def from_httpx(cls, response: httpx.Response) -> iResponse:
        """Create a response from a httpx response."""
        if response.is_success:
            result = iResponse.iResult()
            for f in fields(result):
                header = f.metadata.get("header")
                if header and header in response.headers:
                    setattr(result, f.name, response.headers[header])
            if response.headers.get("Content-Type") == "application/json":
                try:
                    result.response = response.json()
                except ValueError:
                    result.err = iResponse.iError(
                        code=response.status_code, error="Invalid JSON", response=response.text
                    )
                    return result
                result.response = response.text
                return result
        # Nox 2XX response. Fire error
        return cls(
            err=iResponse.iError(
                code=response.status_code,
                error=response.reason_phrase,
                response=response.text or "Request failed (Unknown reason)",
            )
        )

    @dataclass
    class iError:
        """Error response."""

        code: int
        error: str
        response: str

    @dataclass
    class iResult:
        """Result response."""

        # Add Headers as metadata so we can map them to the response
        country_code: str | None = field(
            default=None,
            metadata={
                "header": "X-Apple-ID-Account-Country",
                "config": "client_settings.countryCode",
            },
        )
        trust_token: str | None = field(
            default=None,
            metadata={
                "header": "X-Apple-TwoSV-Trust-Token",
                "config": "tokens.trust",
            },
        )
        session_token: str | None = field(
            default=None,
            metadata={
                "header": "X-Apple-Session-Token",
                "config": "tokens.xAppleSessionToken",
            },
        )
        session_id: str | None = field(
            default=None,
            metadata={
                "header": "X-Apple-ID-Session-Id",
                "config": "account.session_id",
            },
        )
        scnt: str | None = field(
            default=None,
            metadata={
                "header": "scnt",
                "config": "client_settings.scnt",
            },
        )
        # Cath all for json response
        response: Dict[str, any] | str | None = None

        def update(self, target: Config):
            """Update the config with the result data."""
            for f in fields(self):
                value = getattr(self, f.name)
                if value != f.default and "config" in f.metadata:
                    target.update({f.metadata["config"]: value})


class iBaseSession:
    def __init__(self, config: Config, client: httpx.AsyncClient | None = None):
        self._config = config
        self._httpx = client or httpx.AsyncClient(follow_redirects=True)

        # Store last response
        self._response: httpx.Response | None = None
        self._httpx.event_hooks["request"].append(lambda value: setattr(self, "_response", value))

        # set password filter
        PyiCloudPasswordFilter.register(self, logger=get_logger("http"))

    async def __aenter__(self):
        # Set headers
        self._httpx.headers.update(
            {
                "Origin": iConstants.HOME_ENDPOINT,
                "Referer": f"{iConstants.HOME_ENDPOINT}/",
            }
        )
        return self._httpx

    async def __aexit__(self, exc_type, exc, tb):
        if self._response:
            # Update session config
            for header, key in self.HEADER_DATA.items():
                if header in self._response.headers:
                    self._config.update({key: self._response.headers[header]})
        await self._httpx.close()

    @property
    def response(self) -> iResponse:
        assert self._response, "No response available"
        return iResponse.from_httpx(self._response)


@allow_from("post")
@configure
class iLogin(iBaseSession):
    ENDPOINT = "https://idmsa.apple.com/appleauth/auth/signin"

    async def __aenter__(self):
        await super().__aenter__()
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
            "X-Apple-OAuth-State": self._config["client_settings.client_id"],
            "X-Apple-Widget-Key": "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d",
        }
        # Set headers
        self._httpx.headers.update(headers)
        # Set params
        self._httpx.params = {"isRememberMeEnabled": "true"}
        # Set body
        self._httpx.json = {
            "rememberMe": True,
            "accountName": self._config["account.username"],
            "password": self._config.get("account.password", ""),
            "trustTokens": [*[self._config.get("tokens.trust", [])]],
        }
        return self._httpx


class iRefreshLogin(iLogin):
    """Re-Login to iCloud using available session data."""

    async def __aenter__(self):
        await super().__aenter__()
        # Update headers for POST Request
        headers = {}
        if scnt := self._config.get("client_settings.scnt"):
            headers["scnt"] = scnt
        if ssid := self._config.get("account.session_id"):
            headers["X-Apple-ID-Session-Id"] = ssid
        # Set headers
        self._httpx.headers.update(headers)
        # Update body
        if trust_token := self._config.get("tokens.trust"):
            self._httpx.json["trustTokens"] = [trust_token]

        return self._httpx
