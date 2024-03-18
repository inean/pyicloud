"""Library base file."""

from __future__ import annotations

import json
import httpx

from functools import reduce
from collections import namedtuple

from pyicloud.config import PyiCloudFileConfig as Config
from pyicloud.exceptions import (
    PyiCloud2SARequiredException,
    PyiCloudAPIResponseException,
    PyiCloudException,
    PyiCloudFailedLoginException,
    PyiCloudServiceNotActivatedException,
)
from pyicloud.log import LOGGER, PyiCloudPasswordFilter, get_logger, log_request
from pyicloud.services import (
    AccountService,
    CalendarService,
    ContactsService,
    DriveService,
    FindMyiPhoneServiceManager,
    PhotosService,
    RemindersService,
    UbiquityService,
)

Response = namedtuple("Response", ["result", "err"])


class iConstants:
    AUTH_ENDPOINT = "https://idmsa.apple.com/appleauth/auth"
    HOME_ENDPOINT = "https://www.icloud.com"
    SETUP_ENDPOINT = "https://setup.icloud.com/setup/ws/1"


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
                "Origin": self.HOME_ENDPOINT,
                "Referer": "%s/" % self.HOME_ENDPOINT,
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
            "X-Apple-OAuth-Redirect-URI": self.HOME_ENDPOINT,
            "X-Apple-OAuth-Require-Grant-Code": "true",
            "X-Apple-OAuth-Response-Type": "code",
            "X-Apple-OAuth-Response-Mode": "web_message",
            "X-Apple-OAuth-State": self._config["clientId"],
            "X-Apple-Widget-Key": "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d",
        }
        if scnt := self.config.get("clientSettings.scnt"):
            headers["scnt"] = scnt
        if ssid := self.config.get("clientSettings.xAppleIDSessionId"):
            headers["X-Apple-ID-Session-Id"] = ssid
        # Set headers
        self.httpx.headers.update(headers)

        # Set params
        self.httpx.params = {"isRememberMeEnabled": "true"}
        # Set body
        self.httpx.json = {
            "rememberMe": True,
            "accountName": self._config["username"],
            "password": self._config.get("password", ""),
            "trustTokens": [*[self._config.get("auth.xAppleTwosvTrustToken", [])]],
        }

        return retval

    async def __aexit__(self, exc_type, exc, tb):
        # If no Status 200 OK response, Clean up cookies
        return await super().__aexit__(exc_type, exc, tb)


class PyiCloudSession(httpx.Client):
    """iCloud session."""

    SETUP_ENDPOINT = "https://setup.icloud.com/setup/ws/1"

    HEADER_DATA = {
        "X-Apple-ID-Account-Country": "auth.accountCountryCode",
        "X-Apple-ID-Session-Id": "clientSettings.xAppleIDSessionId",
        "X-Apple-Session-Token": "auth.token",
        "X-Apple-TwoSV-Trust-Token": "auth.xAppleTwosvTrustToken",
        "scnt": "clientSettings.scnt",
    }
    BASE_COOKIES: list[str] = ["dslang", "site"]
    LOGIN_COOKIES: list[str] = ["aasp"]
    LOGGED_COOKIES: list[str] = [
        "acn01",
        "X-APPLE-DS-WEB-SESSION-TOKEN",
        "X-APPLE-UNIQUE-CLIENT-ID",
        "X-APPLE-WEBAUTH-LOGIN",
        "X-APPLE-WEBAUTH-USER",
        "X-APPLE-WEBAUTH-VALIDATE",
        *BASE_COOKIES,
        *LOGIN_COOKIES,
    ]

    VERIFY_COOKIES: list[str] = [
        "X-APPLE-WEBAUTH-HSA-LOGIN",
        *BASE_COOKIES,
        *LOGGED_COOKIES,
    ]

    VERIFIED_COOKIES: list[str] = [
        "X-APPLE-WEBAUTH-FMIP",
        "X-APPLE-WEBAUTH-HSA-TRUST",
        "X-APPLE-WEBAUTH-TOKEN",
        *BASE_COOKIES,
        *LOGGED_COOKIES,
    ]

    JSON_MIMETYPES = ["application/json", "text/json"]

    def __init__(self, owner, auth_callback=None, error_callback=None):
        super().__init__(follow_redirects=True)

        # init elements
        self._owner = owner
        self._config = owner.config

        self._auth_callback = auth_callback or self._owner.authenticate
        self._error_callback = error_callback or self._owner._raise_error

        # set password filter
        PyiCloudPasswordFilter.register(self, logger=get_logger("http"))

    def _update_session(self, response):
        for header, value in self.HEADER_DATA.items():
            if header_value := response.headers.get(header):
                split_value = value.split(".")
                nested, key = split_value[:-1], split_value[-1]
                reduce(lambda v, k: v[k], nested, self._config)[key] = header_value

        # Save session_data to file
        self._config.save()
        LOGGER.debug("Saved session data to %s", self._config._session_file)

        return response.headers.get("Content-Type", "").split(";")[0]

    def _get_auth_headers(self, overrides=None):
        headers = {
            "Accept": "*/*",
            "Content-Type": "application/json",
            "X-Apple-OAuth-Client-Id": "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d",
            "X-Apple-OAuth-Client-Type": "firstPartyAuth",
            "X-Apple-OAuth-Redirect-URI": "https://www.icloud.com",
            "X-Apple-OAuth-Require-Grant-Code": "true",
            "X-Apple-OAuth-Response-Mode": "web_message",
            "X-Apple-OAuth-Response-Type": "code",
            "X-Apple-OAuth-State": self._config["clientId"],
            "X-Apple-Widget-Key": "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d",
        }
        if overrides:
            headers.update(overrides)
        return headers

    @log_request
    def request(self, method, url, logger=LOGGER, **kwargs):  # pylint: disable=arguments-differ
        has_retried = kwargs.pop("retried", False)
        response = super().request(method, url, **kwargs)

        # Save response cookies to file
        self._config.cookies.update(response.cookies)
        self._config.cookies.save()

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
                    except PyiCloudAPIResponseException:
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
            api_error = PyiCloudAPIResponseException(response.reason_phrase, response.status_code, retry=True)
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


# class PyiAccount(BaseAccount):
#     def __init__(self, config: Config | None = None, **kwargs) -> None:
#         config = config or Config()
#         super().__init__(config)

#         # Update config after setting apple_id
#         self.config = config or Config()
#         self.config.update(kwargs)

#     def _set_states(self):
#         self._disconnected = Disconnected(self)
#         self._signin = SignIn(self)
#         self._logged = Logged(self)

#     def _set_links(self):
#         self._disconnected.add_link(ConditionalLink(self._logged, self._logged.is_signed))
#         self._disconnected.add_link(Link(self._signin))
#         self._signin.add_link(ConditionalLink(self._logged, self._logged.is_signed))
#         self._signin.add_link(RetryLink(self._signin, retries=2))

#     def on_signin(self) -> str:
#         raise NotImplementedError

#     def on_verify_from(self) -> str:
#         raise NotImplementedError

#     def on_verify(self) -> str:
#         raise NotImplementedError


class PyiCloudUser:
    """
    A base authentication class for the iCloud service. Handles the
    authentication required to access iCloud services.
    """

    STATES = [
        "disconnected",
        "sigin",
        "authorized",
    ]

    def __init__(self, config: Config | None = None, **kwargs):
        # Public Props
        self.params = {}

        self._ws = {}
        self._session = {}
        self._config = None

        # Update config after setting apple_id
        config = config or Config()
        config.update(kwargs)

        # Store config file
        self.config = config

        # Update config after setting apple_id. If username
        # and password are provided, config will be updated data from config files
        self._client = PyiCloudSession(self)
        self._client.verify = self.config["verify"]
        self._client.headers.update(
            {
                "Origin": iConstants.HOME_ENDPOINT,
                "Referer": f"{iConstants.HOME_ENDPOINT}/",
            }
        )

    def set_transitions(self):
        self.add_transition("signin", self._disconnected, self._signin)
        self.add_transition("verify", self._signin, self._logged)

    def _condition_is_logged(self):
        """Returns True if logged."""
        if not self.config["auth"]["token"]:
            LOGGER.debug("Missing session token")
        cookies, missing = self.config.cookies.fetch(self.config.cookies.LOGGED_COOKIES)

        missing and LOGGER.debug("Missing cookies: {}".format(missing))
        return cookies, missing

    async def login(self, username, password) -> Response[dict | None, dict | None]:
        """Fetch a valid session token."""

        LOGGER.debug(f"Authenticating as {username}")

        # Define login client info object
        x_apple_ifd_client_info = {
            "U": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/603.3.1 (KHTML, like Gecko) Version/10.1.2 Safari/603.3.1",
            "L": self.config["clientSettings"]["locale"],
            "Z": self.config["clientSettings"]["timeoffset"],
            "V": "1.1",
            "F": "",
        }
        # Prepare Headers
        headers = {
            "Content-Type": "application/json",
            "Referer": iConstants.AUTH_ENDPOINT,
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/603.3.1 (KHTML, like Gecko) Version/10.1.2 Safari/603.3.1",
            "Origin": "https://idmsa.apple.com",
            "X-Apple-Widget-Key": self.config["clientSettings"]["xAppleWidgetKey"],
            "X-Requested-With": "XMLHttpRequest",
            "X-Apple-I-FD-Client-Info": json.dumps(x_apple_ifd_client_info),
        }

        # Prepare data object to post with login info
        async with httpx.AsyncClient() as client:
            r = await client.post(
                iConstants.AUTH_ENDPOINT,
                headers=headers,
                json={"accountName": username, "password": password, "rememberMe": True, "trustTokens": []},
            )

        # If there are any request errors
        if not r.is_success:
            return Response(None, {"error": "Request failed", "code": r.status_code, "response": r.text})

        # Parse JSON response
        try:
            json_body = r.json()
        except json.JSONDecodeError:
            return Response(None, {"error": "Invalid JSON response", "code": r.status_code, "response": r.text})

        # Extract session info from headers
        result = {
            "session_token": r.headers.get("x-apple-session-token"),
            "session_id": r.headers.get("x-apple-id-session-id"),
            "scnt": r.headers.get("scnt"),
            "response": json_body,
        }
        err = None
        if result["session_token"] is None:
            err = {"error": "No session token", "code": r.status_code, "response": r.text}

        return Response[result, err]

    async def verify(self, callback: callable = None, trust_token: str = "") -> Response[dict | None, dict | None]:
        """Fetch a valid trust token"""
        params = {
            "clientBuildNumber": self.config["clientSettings"]["clientBuildNumber"],
            "clientId": self.config["clientId"],
            "clientMasteringNumber": self.config["clientSettings"]["clientMasteringNumber"],
        }
        headers = {
            "Content-Type": "text/plain",
            "Referer": "https://www.icloud.com/",
            "Accept": "*/*",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/603.3.1 (KHTML, like Gecko) Version/10.1.2 Safari/603.3.1",
            "Origin": "https://www.icloud.com",
        }
        body = {
            "trustToken": trust_token,
            "extended_login": True,
            "accountCountryCode": self.config["account_country"],
            "dsWebAuthToken": self.config["auth"]["token"],
        }
        # Prepare data object to post with login info
        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"{iConstants.SETUP_ENDPOINT}/accountLogin", headers=headers, params=params, json=body
            )

        # If there are any request errors
        if not r.is_success:
            return Response(None, {"error": "Request failed", "code": r.status_code, "response": r.text})

        # Parse JSON response
        try:
            json_body = r.json()
        except json.JSONDecodeError:
            return Response(None, {"error": "Invalid JSON response", "code": r.status_code, "response": r.text})

        # Extract session info from headers
        result = {
            "session_token": r.headers.get("x-apple-session-token"),
            "session_id": r.headers.get("x-apple-id-session-id"),
            "scnt": r.headers.get("scnt"),
            "response": json_body,
        }
        err = None
        if result["session_token"] is None:
            err = {"error": "No session token", "code": r.status_code, "response": r.text}

        return Response[result, err]

    def authenticate(self, force_refresh=False, service=None):
        """
        Handles authentication, and persists cookies so that
        subsequent logins will not cause additional e-mails from Apple.
        """
        LOGGER.debug("Start auth handshake")
        if self.config["auth"]["token"] and not force_refresh:
            LOGGER.info("Using session token")
            try:
                self._validate()
                self._ws = self._session["webservices"]
                LOGGER.info("Authentication with session token completed successfully")
                return
            except PyiCloudAPIResponseException:
                LOGGER.info("Invalid authentication token, will log in from scratch.")
                self.config["auth"]["token"] = None

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
            self._authenticate_fetch_session_token()

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
                self._client.post(f"{iConstants.SETUP_ENDPOINT}/accountLogin", data=json.dumps(data))
                self._validate()
            except PyiCloudAPIResponseException as error:
                msg = "Invalid email/password combination."
                self._password = ""
                raise PyiCloudFailedLoginException(msg, error) from error

    def _authenticate_fetch_session_token(self):
        LOGGER.debug("Authenticating as %s", self.apple_id)

        # Prepare Headers
        headers = self._client._get_auth_headers()
        if scnt := self.config["clientSettings"]["scnt"]:
            headers["scnt"] = scnt
        if ssid := self.config["clientSettings"]["xAppleIDSessionId"]:
            headers["X-Apple-ID-Session-Id"] = ssid

        # Prepare content
        data = {"accountName": self.apple_id, "rememberMe": True, "trustTokens": []}
        if self.password:
            data["password"] = self.password
        if trust_token := self.config["auth"]["xAppleTwosvTrustToken"]:
            data["trustTokens"] = [trust_token]

        try:
            self._client.post(
                f"{iConstants.AUTH_ENDPOINT}/signin",
                params={"isRememberMeEnabled": "true"},
                data=json.dumps(data),
                headers=headers,
            )
        except PyiCloudAPIResponseException as error:
            msg = "Invalid email/password combination."
            raise PyiCloudFailedLoginException(msg, error) from error
            # If we are here, we are authenticated,
            # session_token will be available. Don't throw an error
            # but stop here. let the caller handle it.
        if not (token := self.config["auth"]["token"]):
            self.password = ""
            return

        self._authenticate_fetch_trust_token(token)

    def _validate(self):
        """Checks if the current cookie set is still valid."""
        LOGGER.debug("Renewing session using cookies")
        try:
            req = self._client.post(f"{iConstants.SETUP_ENDPOINT}/validate", data="null")
            LOGGER.debug("Session token is still valid")
            self._session = req.json()
        except PyiCloudAPIResponseException as err:
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

        api_error = PyiCloudAPIResponseException(reason, code)
        LOGGER.error(api_error)
        raise api_error

    def _authenticate_fetch_trust_token(self, session_token: str | None = None):
        """Authenticate using session token."""
        data = {
            "accountCountryCode": self.config["auth"]["accountCountryCode"],
            "dsWebAuthToken": session_token or self.config["auth"]["token"],
            "extended_login": True,
            "trustToken": self.config["auth"]["xAppleTwosvTrustToken"],
        }
        try:
            req = self._client.post(f"{iConstants.SETUP_ENDPOINT}/accountLogin", data=json.dumps(data))
            self._session = req.json()
        except PyiCloudAPIResponseException as error:
            msg = "Invalid authentication token."
            raise PyiCloudFailedLoginException(msg, error) from error

    def send_verification_code(self, device):
        """Requests that a verification code is sent to the given device."""
        data = json.dumps(device)
        request = self._client.post(
            f"{iConstants.SETUP_ENDPOINT}/sendVerificationCode",
            params=self.params,
            data=data,
        )
        return request.json().get("success", False)

    def validate_verification_code(self, device, code):
        """Verifies a verification code received on a trusted device."""
        device.update({"verificationCode": code, "trustBrowser": True})
        data = json.dumps(device)

        try:
            self._client.post(
                f"{iConstants.SETUP_ENDPOINT}/validateVerificationCode",
                params=self.params,
                data=data,
            )
        except PyiCloudAPIResponseException as error:
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

        if scnt := self.config["clientSettings"]["scnt"]:
            headers["scnt"] = scnt

        if ssid := self.config["clientSettings"]["xAppleIDSessionId"]:
            headers["X-Apple-ID-Session-Id"] = ssid

        try:
            self._client.post(
                f"{iConstants.AUTH_ENDPOINT}/verify/trusteddevice/securitycode",
                data=json.dumps(data),
                headers=headers,
            )
        except PyiCloudAPIResponseException as error:
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

        if scnt := self.config["clientSettings"]["scnt"]:
            headers["scnt"] = scnt

        if ssid := self.config["clientSettings"]["xAppleIDSessionId"]:
            headers["X-Apple-ID-Session-Id"] = ssid

        try:
            self._client.get(
                f"{iConstants.AUTH_ENDPOINT}/2sv/trust",
                headers=headers,
            )
            self._authenticate_fetch_trust_token()
            return True
        except PyiCloudAPIResponseException:
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
        return self._config["username"] if self._config else ""

    @property
    def config(self) -> Config:
        """Config getter."""
        return self._config

    @config.setter
    def config(self, value: Config):
        assert isinstance(value, Config)

        # Sanity checks
        if self._config == value:
            return
        if self._config and self._config != value:
            raise PyiCloudException("Config cannot be changed")
        self._config, old_apple_id = value, self.apple_id

        # Add a filter so password is not logged
        PyiCloudPasswordFilter.register(self._config)
        self._config.ee.on("changed.password", PyiCloudPasswordFilter.on_changed_password)

        # Listen to username updates and reload config if necessary
        self._config.ee.on("username.changed", lambda *_: self._config.load(update_path=True))
        self._config.ee.emit("username.changed", old_apple_id, self.apple_id)

    @property
    def password(self):
        """Password getter."""
        return self._config["password"] if self._config else ""

    @password.setter
    def password(self, value):
        self._config["password"] = value

    @property
    def session(self):
        """Session getter."""
        if not self._ws:
            raise AttributeError("Session is not authenticated")
        return self._client

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
            f"{iConstants.SETUP_ENDPOINT}/listDevices",
            params=self.params,
        )
        return request.json().get("devices")

    def __str__(self):
        return f"iCloud API: {self.apple_id}"

    def __repr__(self):
        return f"<{self}>"


# Alias
class PyiCloud(PyiCloudUser):
    def __init__(self, username: str, password: str = "", config: Config | None = None):
        config = config or Config()
        config.update({"username": username, "password": password})
        PyiCloudUser.__init__(self, config)


class PyiCloudServices:
    """
    A base authentication class for the iCloud service. Handles the
    authentication required to access iCloud services.

    Usage:
        from pyicloud import PyiCloudService
        pyicloud = PyiCloudService('username@apple.com', 'password')
        pyicloud.iphone.location()
    """

    class _Proxy:
        def __init__(self, cls, service, endpoint, params):
            self._endpoint = endpoint
            self._service = service
            self._params = params
            # Private Props
            self.__cls = cls
            self.__target = None

        def authenticate(self):
            """Authenticate the service."""
            self._endpoint.authenticate(service=self._service)
            self.__target = self.__cls(self._endpoint[self._service], **self._params)

        def __getattr__(self, name):
            if not self.__target:
                raise Exception("You must authenticate before accessing this attribute.")
            return getattr(self._service, name)

        def __getitem__(self, name):
            if not self.__target:
                raise Exception("You must authenticate before accessing this attribute.")
            return self.__target[name]

    def __init__(self, endpoint):
        self._endpoint = endpoint
        # Expensive services
        self._drive = None
        self._photos = None
        self._files = None

    @property
    def devices(self):
        """Returns all devices."""
        cls = FindMyiPhoneServiceManager
        service = "findme"
        kwargs = {
            "session": self._endpoint.session,
            "params": self._endpoint.params,
            "with_family": self._endpoint.config["withFamily"],
        }
        if service not in self._endpoint:
            return self._Proxy(cls, service, self._endpoint, kwargs)
        return cls(self._endpoint[service], **kwargs)

    @property
    def iphone(self):
        """Returns the iPhone."""
        return self.devices[0]

    @property
    def account(self):
        """Gets the 'Account' service."""
        cls = AccountService
        service = "account"
        kwargs = {
            "service_root": self._endpoint[service],
            "session": self._endpoint.session,
            "params": self._endpoint.params,
        }
        if service not in self._endpoint:
            return self._Proxy(cls, service, self._endpoint, kwargs)
        return cls(**kwargs)

    @property
    def files(self):
        """Gets the 'File' service."""
        cls = UbiquityService
        service = "ubiquity"
        kwargs = {
            "service_root": self._endpoint[service],
            "session": self._endpoint.session,
            "params": self._endpoint.params,
        }
        if service not in self._endpoint:
            return self._Proxy(cls, service, self._endpoint, kwargs)
        self._files = cls(**kwargs)
        return self._files

    @property
    def photos(self):
        """Gets the 'Photo' service."""
        cls = PhotosService
        service = "ckdatabasews"
        kwargs = {
            "service_root": self._endpoint[service],
            "session": self._endpoint.session,
            "params": self._endpoint.params,
        }
        if service not in self._endpoint:
            return self._Proxy(cls, service, self._endpoint, kwargs)
        self._photos = cls(**kwargs)
        return self._photos

    @property
    def calendar(self):
        """Gets the 'Calendar' service."""
        cls = CalendarService
        service = "calendar"
        kwargs = {
            "service_root": self._endpoint[service],
            "session": self._endpoint.session,
            "params": self._endpoint.params,
        }
        if service not in self._endpoint:
            return self._Proxy(cls, service, self._endpoint, kwargs)
        return cls(**kwargs)

    @property
    def contacts(self):
        """Gets the 'Contacts' service."""
        cls = ContactsService
        service = "contacts"
        kwargs = {
            "service_root": self._endpoint[service],
            "session": self._endpoint.session,
            "params": self._endpoint.params,
        }
        if service not in self._endpoint:
            return self._Proxy(cls, service, self._endpoint, kwargs)
        return cls(**kwargs)

    @property
    def reminders(self):
        """Gets the 'Reminders' service."""
        cls = RemindersService
        service = "reminders"
        kwargs = {
            "service_root": self._endpoint[service],
            "session": self._endpoint.session,
            "params": self._endpoint.params,
        }
        if service not in self._endpoint:
            return self._Proxy(cls, service, self._endpoint, kwargs)
        return cls(**kwargs)

    @property
    def drive(self):
        """Gets the 'Drive' service."""
        cls = DriveService
        service = "drivews"
        kwargs = {
            "service_root": self._endpoint[service],
            "document_root": self._endpoint["docws"],
            "session": self._endpoint.session,
            "params": self._endpoint.params,
        }
        if service not in self._endpoint:
            return self._Proxy(cls, service, self._endpoint, kwargs)
        self._drive = cls(**kwargs)
        return self._drive

    def __str__(self):
        return f"iCloudFactory API: {self._endpoint.apple_id}"

    def __repr__(self):
        return f"<{self}>"
