"""Legacy-compatible HTTP session adapter for service calls."""

from __future__ import annotations

from typing import Any, Callable

import httpx

from pyicloud.exceptions import PyiCloudAPIResponseError
from pyicloud.log import LOGGER
from pyicloud.log.httpx import LoggerHook, LogTransport
from pyicloud.models.cookies import Cookies
from pyicloud.models.settings import Settings
from pyicloud.paths import CookiesJar, SettingsFile


class LegacyServiceSessionAdapter(httpx.Client):
    """HTTPX client with legacy iCloud session update and error parsing behavior."""

    HEADER_DATA = {
        "X-Apple-ID-Account-Country": "account.country_code",
        "X-Apple-ID-Session-Id": "account.session_id",
        "X-Apple-Session-Token": "token.session",
        "X-Apple-TwoSV-Trust-Token": "token.trust",
        "scnt": "client_settings.scnt",
    }

    JSON_MIMETYPES = ("application/json", "text/json")

    def __init__(
        self,
        *,
        settings: Settings,
        auth_callback: Callable[..., Any] | None = None,
        error_callback: Callable[[str | int | None, str], None] | None = None,
    ):
        super().__init__(
            follow_redirects=True,
            transport=LogTransport(),
            event_hooks={"response": [LoggerHook.log_response_hook]},
        )
        self._settings = settings
        self._auth_callback = auth_callback or (lambda *_args, **_kwargs: None)
        self._error_callback = error_callback or self._raise_error

    def _raise_error(self, code: str | int | None, reason: str) -> None:
        raise PyiCloudAPIResponseError(reason, code)

    def _update_session(self, response: httpx.Response) -> str:
        for header, key in self.HEADER_DATA.items():
            if value := response.headers.get(header):
                self._settings[key] = value

        settings_file = SettingsFile(self._settings)
        LOGGER.debug("Saved session data to %s", settings_file)
        settings_file.saves()

        return response.headers.get("content-type", "").split(";")[0]

    def _get_auth_headers(self, overrides: dict[str, Any] | None = None) -> dict[str, Any]:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Apple-OAuth-Client-Id": "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d",
            "X-Apple-OAuth-Client-Type": "firstPartyAuth",
            "X-Apple-OAuth-Redirect-URI": "https://www.icloud.com",
            "X-Apple-OAuth-Require-Grant-Code": "true",
            "X-Apple-OAuth-Response-Mode": "web_message",
            "X-Apple-OAuth-Response-Type": "code",
            "X-Apple-OAuth-State": self._settings["client_settings.client_id"],
            "X-Apple-Widget-Key": "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d",
        }
        if overrides:
            headers.update(overrides)
        return headers

    def request(self, method, url, logger=LOGGER, **kwargs):  # pylint: disable=arguments-differ
        has_retried = kwargs.pop("retried", False)
        response = super().request(method, url, **kwargs)

        if response.cookies:
            cookies = Cookies({})
            CookiesJar(cookies).loads(username=self._settings.account.username)
            for cookie in Cookies.model_validate(response.cookies):
                cookies[cookie.key] = cookie
            CookiesJar(cookies).saves(username=self._settings.account.username)

        content_type = self._update_session(response)
        if not content_type and response.content:
            try:
                response.json()
                content_type = "application/json"
            except Exception:  # noqa: BLE001
                pass

        logger.debug("Response Code: %s", response.status_code)

        if (
            not response.is_success
            and (content_type not in self.JSON_MIMETYPES or response.status_code in [421, 450, 500])
            and not has_retried
            and response.status_code in [421, 450, 500]
        ):
            if response.status_code == 450:
                try:
                    self._auth_callback(True, "find")
                except PyiCloudAPIResponseError:
                    logger.debug("Re-authentication callback failed")
            api_error = PyiCloudAPIResponseError(response.reason_phrase, response.status_code, retry=True)
            logger.debug(api_error)
            kwargs["retried"] = True
            return self.request(method, url, **kwargs)

        if not response.is_success and (content_type not in self.JSON_MIMETYPES or response.status_code in [421, 450, 500]):
            self._error_callback(response.status_code, response.reason_phrase)

        if content_type not in self.JSON_MIMETYPES:
            return response

        try:
            data = response.json()
        except Exception:  # noqa: BLE001
            logger.warning("Failed to parse response with JSON mimetype")
            return response

        self._parse_error(data)
        return response

    def _parse_error(self, data: Any) -> None:
        if not isinstance(data, dict):
            return

        reason = data.get("errorMessage")
        reason = reason or data.get("reason")
        reason = reason or data.get("errorReason")
        if not reason and isinstance(data.get("error"), str):
            reason = data.get("error")
        if not reason and data.get("error"):
            reason = "Unknown reason"

        code = data.get("errorCode")
        if not code and data.get("serverErrorCode"):
            code = data.get("serverErrorCode")

        if reason:
            self._error_callback(code, reason)
