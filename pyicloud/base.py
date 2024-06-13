"""Library base file."""

from __future__ import annotations

import json
import os

import httpx

from pyicloud.constants import Endpoints
from pyicloud.exceptions import (
    PyiCloud2SARequiredException,
    PyiCloudAPIResponseError,
    PyiCloudError,
    PyiCloudFailedLoginException,
    PyiCloudServiceNotActivatedException,
)
from pyicloud.log import LOGGER, PyiCloudPasswordFilter, logger_get
from pyicloud.log.httpx import LoggerHook, LogTransport
from pyicloud.models.cookies import Cookies
from pyicloud.models.settings import Settings
from pyicloud.paths import CookiesJar, SettingsFile
from pyicloud.utils.decorators import Deprecated


class PyiCloudSession(httpx.Client, metaclass=Deprecated):
    """iCloud session."""

    SETUP_ENDPOINT = "https://setup.icloud.com/setup/ws/1"

    HEADER_DATA = {
        "X-Apple-ID-Account-Country": "account.country_code",
        "X-Apple-ID-Session-Id": "account.session_id",
        "X-Apple-Session-Token": "token.session",
        "X-Apple-TwoSV-Trust-Token": "token.trust",
        "scnt": "client_settings.scnt",
    }

    JSON_MIMETYPES = ["application/json", "text/json"]

    def __init__(self, owner, auth_callback=None, error_callback=None):
        super().__init__(
            follow_redirects=True,
            transport=LogTransport(),
            event_hooks={"response": [LoggerHook.log_response_hook]},
        )

        # init elements
        self._owner = owner
        self._settings: Settings = owner.config

        self._auth_callback = auth_callback or self._owner.authenticate
        self._error_callback = error_callback or self._owner._raise_error

        # set password filter
        PyiCloudPasswordFilter.register(self, logger=logger_get("http"))

    def _update_session(self, response):
        for header, key in self.HEADER_DATA.items():
            if value := response.headers.get(header):
                self._settings[key] = value

        # Save session_data to file
        settings_file = SettingsFile(self._settings)
        LOGGER.debug(f"Saved session data to {os.fspath(settings_file)}")
        settings_file.saves()

        return response.headers.get("content-type", "").split(";")[0]

    def _get_auth_headers(self, overrides=None):
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

        # Update response cookies to file
        if response.cookies:
            cookies = Cookies({})
            CookiesJar(cookies).loads(username=self._settings.account.username)
            for cookie in Cookies.model_validate(response.cookies):
                cookies[cookie.key] = cookie
            CookiesJar(cookies).saves(username=self._settings.account.username)

        # Update session
        content_type = self._update_session(response)

        LOGGER.debug("Response Code: %s", response.status_code)

        if not response.is_success and (content_type not in self.JSON_MIMETYPES or response.status_code == 450):
            # Handle re-authentication for Find My iPhone
            try:
                # pylint: disable=protected-access
                fmip_url = self._owner["findme"]

                if not has_retried and response.status_code == 450 and fmip_url in url:
                    # Handle re-authentication for Find My iPhone
                    LOGGER.debug("Re-authenticating Find My iPhone service")
                    try:
                        # If 450, authentication requires a full sign in to the account
                        self._auth_callback(True, "find")
                    except PyiCloudAPIResponseError:
                        LOGGER.debug("Re-authentication failed")
                    kwargs["retried"] = True
                    return self.request(method, url, **kwargs)
            except Exception:
                pass

        if (
            not response.is_success
            and (content_type not in self.JSON_MIMETYPES or response.status_code in [421, 450, 500])
            and (not has_retried and response.status_code in [421, 450, 500])
        ):
            api_error = PyiCloudAPIResponseError(response.reason_phrase, response.status_code, retry=True)
            logger.debug(api_error)
            kwargs["retried"] = True
            return self.request(method, url, **kwargs)

        if not response.is_success and (
            content_type not in self.JSON_MIMETYPES or response.status_code in [421, 450, 500]
        ):
            self._error_callback(response.status_code, response.reason_phrase)

        if content_type not in self.JSON_MIMETYPES:
            return response

        try:
            data = response.json()
        except Exception:
            logger.warning("Failed to parse response with JSON mimetype")
            return response

        self._parse_error(data)

        return response

    def _parse_error(self, data):
        if isinstance(data, dict):
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


class PyiCloudUser(metaclass=Deprecated):
    """
    A base authentication class for the iCloud service. Handles the
    authentication required to access iCloud services.
    """

    session_cls = PyiCloudSession

    def __init__(self, config: Settings):
        # Public Props
        self._params: dict = {}

        self._ws: dict = {}
        self._session: dict = {}
        self._config: Settings | None = None

        # Store config file
        self.config = config

        # Update config after setting apple_id. If username
        # and password are provided, config will be updated data from config files
        self._client = self.session_cls(self)
        self._client.headers.update(
            {
                "Origin": Endpoints.HOME,
                "Referer": f"{Endpoints.HOME}/",
            }
        )

    def authenticate(self, force_refresh=False, service=None):
        """
        Handles authentication, and persists cookies so that
        subsequent logins will not cause additional e-mails from Apple.
        """
        LOGGER.debug("Start auth handshake")
        if self.config.token.session and not force_refresh:
            LOGGER.info("Using session token")
            try:
                self._validate()
                self._ws = self._session["webservices"]
                LOGGER.info("Authentication with session token completed successfully")
                return
            except PyiCloudAPIResponseError:
                LOGGER.info("Invalid authentication token, will log in from scratch.")
                self.config.token.session = None

        login_successful = False
        if service:
            LOGGER.info(f"Authenticating as {self.apple_id} for {service}")
            try:
                self._authenticate_setup_service(service)
                login_successful = True
            except Exception:
                LOGGER.info(f"Could not log into {service}. Attempting brand new login.")

        if not login_successful:
            LOGGER.info(f"Start full authenticating as {self.apple_id}")
            session_token = self._authenticate_fetch_session_token()
            self._authenticate_fetch_trust_token(session_token)

        self._ws = self._session.get("webservices", {})
        if self._ws:
            LOGGER.info("Authentication completed successfully")

    def _authenticate_setup_service(self, service):
        """Authenticate to a specific service using credentials."""
        data = {
            "appName": service,
            "apple_id": self.apple_id,
            "password": self.password,
        }
        app = self._session["apps"][service]
        if app.get("canLaunchWithOneFactor", False):
            LOGGER.debug(f"Authenticating for {service} as {self.apple_id} with OneFactor")
            try:
                self._client.post(f"{Endpoints.INIT}/accountLogin", json=data)
                self._validate()
            except PyiCloudAPIResponseError as error:
                msg = "Invalid email/password combination."
                self.password = ""
                raise PyiCloudFailedLoginException(msg, error) from error

    def _authenticate_fetch_session_token(self):
        LOGGER.debug("Authenticating as %s", self.apple_id)

        # Prepare Headers
        headers = self._client._get_auth_headers()
        if scnt := self.config.client_settings.scnt:
            headers["scnt"] = scnt
        if ssid := self.config.account.session_id:
            headers["X-Apple-ID-Session-Id"] = ssid

        # Prepare content
        data = {"accountName": self.apple_id, "rememberMe": True, "trustTokens": []}
        if self.password:
            data["password"] = self.password
        if trust_token := self.config.token.trust:
            data["trustTokens"] = [trust_token]

        try:
            self._client.post(
                f"{Endpoints.AUTH}/signin",
                params={"isRememberMeEnabled": "true"},
                json=data,
                headers=headers,
            )
        except PyiCloudAPIResponseError as error:
            msg = "Invalid email/password combination."
            raise PyiCloudFailedLoginException(msg, error) from error
            # If we are here, we are authenticated,
            # session_token will be available. Don't throw an error
            # but stop here. let the caller handle it.
        if not (token := self.config.token.session):
            self.password = ""
            return
        return token

    def _validate(self):
        """Checks if the current cookie set is still valid."""
        LOGGER.debug("Renewing session using cookies")
        try:
            req = self._client.post(f"{Endpoints.INIT}/validate")
            LOGGER.debug("Session token is still valid")
            self._session = req.json()
            self.config.account.model_validate(self._session)
        except PyiCloudAPIResponseError as err:
            LOGGER.debug("Invalid authentication token")
            raise err

    def _raise_error(self, code, reason):
        if self.requires_2sa and reason == "Missing X-APPLE-WEBAUTH-TOKEN cookie":
            raise PyiCloud2SARequiredException(self.apple_id)
        if code in ("ZONE_NOT_FOUND", "AUTHENTICATION_FAILED"):
            reason = "Please log into https://icloud.com/ to manually finish setting up your iCloud service"
            api_error = PyiCloudServiceNotActivatedException(reason, code)
            LOGGER.error(api_error)

            raise (api_error)
        if code == "ACCESS_DENIED":
            reason = (
                reason + ".  Please wait a few minutes then try again."
                "The remote servers might be trying to throttle requests."
            )
        if code in [421, 450, 500]:
            reason = "Authentication required for Account."

        api_error = PyiCloudAPIResponseError(reason, code)
        LOGGER.error(api_error)
        raise api_error

    def _authenticate_fetch_trust_token(self, session_token: str | None = None):
        """Authenticate using session token."""

        if not (session_token := session_token or self.config.token.session):
            return
        data = {
            "accountCountryCode": self.config.account.country_code,
            "dsWebAuthToken": session_token,
            "extended_login": True,
            "trustToken": [self.config.token.trust],
        }
        try:
            req = self._client.post(f"{Endpoints.INIT}/accountLogin", json=data)
            self._session = req.json()
        except PyiCloudAPIResponseError as error:
            msg = "Invalid authentication token."
            raise PyiCloudFailedLoginException(msg, error) from error

    def send_verification_code(self, device):
        """Requests that a verification code is sent to the given device."""
        data = json.dumps(device)
        request = self._client.post(
            f"{Endpoints.INIT}/sendVerificationCode",
            params=self._params,
            json=data,
        )
        return request.json().get("success", False)

    def validate_verification_code(self, device, code):
        """Verifies a verification code received on a trusted device."""
        device.update({"verificationCode": code, "trustBrowser": True})
        data = json.dumps(device)

        try:
            self._client.post(
                f"{Endpoints.INIT}/validateVerificationCode",
                params=self._params,
                json=data,
            )
        except PyiCloudAPIResponseError as error:
            if error.code == -21669:
                # Wrong verification code
                return False
            raise

        self.trust_session()

        return not self.requires_2sa

    def validate_2fa_code(self, code):
        """Verifies a verification code received via Apple's 2FA system (HSA2)."""
        data = {"securityCode": {"code": code}}

        headers = self._client._get_auth_headers({"Accept": "application/json"})

        if scnt := self.config.client_settings.scnt:
            headers["scnt"] = scnt

        if ssid := self.config.account.session_id:
            headers["X-Apple-ID-Session-Id"] = ssid

        try:
            self._client.post(
                f"{Endpoints.AUTH}/verify/trusteddevice/securitycode",
                json=data,
                headers=headers,
            )
        except PyiCloudAPIResponseError as error:
            if error.code == -21669:
                # Wrong verification code
                LOGGER.error("Code verification failed.")
                return False
            raise

        LOGGER.debug("Code verification successful.")

        self.trust_session()
        return not self.requires_2sa

    def trust_session(self):
        """Request session trust to avoid user log in going forward."""
        headers = self._client._get_auth_headers()

        if scnt := self.config.client_settings.scnt:
            headers["scnt"] = scnt

        if ssid := self.config.account.session_id:
            headers["X-Apple-ID-Session-Id"] = ssid

        try:
            self._client.get(
                f"{Endpoints.AUTH}/2sv/trust",
                headers=headers,
            )
            self._authenticate_fetch_trust_token()
            return True
        except PyiCloudAPIResponseError:
            LOGGER.error("Session trust failed.")
            return False

    def __getitem__(self, ws_key):
        """Get webservice URL, raise an exception if not exists."""
        if self._ws.get(ws_key) is None:
            raise PyiCloudServiceNotActivatedException("Webservice not available", ws_key)
        return self._ws[ws_key]["url"]

    def __contains__(self, ws_key):
        """Check if webservice exists."""
        return ws_key in self._ws

    @property
    def apple_id(self):
        """Apple ID getter."""
        return self.config.account.username

    @property
    def config(self) -> Settings:
        """Config getter."""
        assert self._config, "Config is not set"
        return self._config

    @config.setter
    def config(self, value: Settings):
        assert isinstance(value, Settings)

        # Sanity checks
        if self._config == value:
            return
        if self._config and self._config != value:
            raise PyiCloudError("Config cannot be changed")
        self._config = value

        # Add a filter so password is not logged
        PyiCloudPasswordFilter.register(self.config)
        self.config.account.events.password.connect(
            lambda x: PyiCloudPasswordFilter.on_changed_password(x, self.config)
        )

        # Listen to username updates and reload config if necessary
        self.config.account.events.username.connect(lambda *_: SettingsFile(self.config).loads())
        self.config.account.events.username.emit()

    @property
    def password(self):
        """Password getter."""
        password = self.config.account.password
        return password.get_secret_value() if password else None

    @password.setter
    def password(self, value):
        self.config.account.password = value

    @property
    def session(self):
        """Session getter."""
        if not self._ws:
            raise AttributeError("Session is not authenticated")
        return self._client

    @property
    def params(self):
        """Params getter."""
        if not self._ws:
            raise AttributeError("Session is not authenticated")
        return self._params

    @property
    def state(self):
        """State getter."""
        return self._session

    @property
    def requires_password(self):
        """Returns True if password is required."""
        return self.password == "" and not self._ws

    @property
    def requires_2sa(self):
        """Returns True if two-step authentication is required."""
        return self._session.get("dsInfo", {}).get("hsaVersion", 0) >= 1 and (
            self._session.get("hsaChallengeRequired", False) or not self.is_trusted_session
        )

    @property
    def requires_2fa(self):
        """Returns True if two-factor authentication is required."""
        return self._session["dsInfo"].get("hsaVersion", 0) == 2 and (
            self._session.get("hsaChallengeRequired", False) or not self.is_trusted_session
        )

    @property
    def is_trusted_session(self):
        """Returns True if the session is trusted."""
        return self._session.get("hsaTrustedBrowser", False)

    @property
    def trusted_devices(self):
        """Returns devices trusted for two-step authentication."""
        request = self._client.get(
            f"{Endpoints.INIT}/listDevices",
            params=self._params,
        )
        return request.json().get("devices")

    def __str__(self):
        return f"iCloud API: {self.apple_id}"

    def __repr__(self):
        return f"<{self}>"


# Alias
class PyiCloud(PyiCloudUser):
    def __init__(self, username: str, password: str | None = None):
        settings = Settings.model_validate({"account": {"username": username}})
        SettingsFile(settings).loads()
        if password:
            settings.account.password = password  # type: ignore
        PyiCloudUser.__init__(self, settings)
