"""Library base file."""

from __future__ import annotations

import json
from http import cookiejar
from pprint import pformat

import httpx

from pyicloud.config import PyiCloudFileConfig
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


class PyiCloudConstants:
    AUTH_ENDPOINT = "https://idmsa.apple.com/appleauth/auth"
    HOME_ENDPOINT = "https://www.icloud.com"
    SETUP_ENDPOINT = "https://setup.icloud.com/setup/ws/1"


class PyiCloudSession(httpx.Client):
    """iCloud session."""

    SETUP_ENDPOINT = "https://setup.icloud.com/setup/ws/1"

    HEADER_DATA = {
        "X-Apple-ID-Account-Country": "account_country",
        "X-Apple-ID-Session-Id": "session_id",
        "X-Apple-Session-Token": "session_token",
        "X-Apple-TwoSV-Trust-Token": "trust_token",
        "scnt": "scnt",
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
        self._config = owner._config

        self._auth_callback = auth_callback or self._owner.authenticate
        self._error_callback = error_callback or self._owner._raise_error

        # set password filter
        PyiCloudPasswordFilter.register(self, logger=get_logger("http"))

    def load_cookies_from_file(self, cookiejar_file):
        """Load cookies from file."""
        lwp_cookie_jar = cookiejar.LWPCookieJar(filename=cookiejar_file)
        try:
            lwp_cookie_jar.load(ignore_discard=True, ignore_expires=True)
            LOGGER.debug("Read cookies from %s", cookiejar_file)
        except FileNotFoundError:
            LOGGER.info("Failed to read cookiejar %s", cookiejar_file)
        self.cookies = httpx.Cookies(lwp_cookie_jar)

    def _save_cookies_to_file(self, cookiejar_file):
        """Save cookies to file."""
        lwp_cookie_jar = cookiejar.LWPCookieJar()
        for cookie in self.cookies.jar:
            lwp_cookie_jar.set_cookie(cookie)
        try:
            # Save LWPCookieJar to file
            LOGGER.debug("Saved cookies to %s", cookiejar_file)
            lwp_cookie_jar.save(filename=cookiejar_file, ignore_discard=True, ignore_expires=True)
        except FileNotFoundError:
            LOGGER.warning("Failed to save cookiejar %s", cookiejar_file)

    def _update_session(self, response):
        content_type = response.headers.get("Content-Type", "").split(";")[0]
        session_updates = {
            value: header_value
            for header, value in self.HEADER_DATA.items()
            if (header_value := response.headers.get(header))
        }
        # Save session to file
        self._owner._session_data.update(session_updates)
        # Save session_data to file
        with open(self._config._session_file, "w", encoding="utf-8") as outfile:
            json.dump(self._owner._session_data, outfile)
            LOGGER.debug("Saved session data to %s", self._config._session_file)

        return content_type

    @log_request
    def request(self, method, url, logger=LOGGER, **kwargs):  # pylint: disable=arguments-differ

        has_retried = kwargs.pop("retried", False)
        response = super().request(method, url, **kwargs)

        # Save cookies to file
        self._save_cookies_to_file(self._config._cookiejar_file)

        # Update session
        content_type = self._update_session(response)

        LOGGER.debug("Response Code: %s", response.status_code)
        LOGGER.debug(pformat(response))

        if not response.is_success and (content_type not in self.JSON_MIMETYPES or response.status_code == 450):
            # Handle re-authentication for Find My iPhone
            try:
                # pylint: disable=protected-access
                fmip_url = self._owner["findme"]
                print(fmip_url, url)

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
            logger.debug(pformat(response))
            logger.warning("Failed to parse response with JSON mimetype")
            return response

        logger.debug(pformat(data))

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


class Event:
    def __init__(self, events, allow_duplicates=True):
        self._events = {event: [] for event in events}

    def subscribe(self, event_name, func):
        if event_name not in self._events:
            raise ValueError(f"No such event: {event_name}")
        if func in self._events[event_name]:
            raise ValueError(f"Function already subscribed to event: {event_name}")
        self._events[event_name].append(func)

    def unsubscribe(self, event_name, func):
        if event_name not in self._events:
            raise ValueError(f"No such event: {event_name}")
        if func not in self._events[event_name]:
            raise ValueError(f"Function not subscribed to event: {event_name}")
        self._events[event_name].remove(func)

    def fire(self, event_name, *args, **kwargs):
        if event_name not in self._events:
            raise ValueError(f"No such event: {event_name}")
        for subscriber in self._events[event_name]:
            subscriber(*args, **kwargs)


class PyiCloudUser:
    """
    A base authentication class for the iCloud service. Handles the
    authentication required to access iCloud services.

    Usage:
        from pyicloud import PyiCloud

        pyicloud = PyiCloud.from_config('username@apple.com')
        services = pyicloud.services()

        # Some services don't require 2FA, so we can authenticate directly
        #
        auth_challenge = services.iphone.authenticate()
        while auth_challenge.err():
            if auth_challenge.requires_2fa:
                ...
            if auth_challenge.requires_2sa:
                ...
            if auth_challenge.requires_password:
                ...

        services.iphone.location()

    """

    AUTH_ENDPOINT = "https://idmsa.apple.com/appleauth/auth"
    HOME_ENDPOINT = "https://www.icloud.com"
    SETUP_ENDPOINT = "https://setup.icloud.com/setup/ws/1"

    def __init__(self, apple_id: str, password: str = "", config=PyiCloudFileConfig.create()):
        # Public Props
        self.params = {}

        # Private Props
        self._apple_id = ""
        self._password = ""

        self._ws = {}
        self._state = {}
        self._config = config

        self._events = Event(["apple_id_changed", "password_changed"])

        # Update config after setting apple_id
        self.config = config

        self._session = PyiCloudSession(self)
        self._session.verify = self.config.verify
        self._session.headers.update({"Origin": self.HOME_ENDPOINT, "Referer": "%s/" % self.HOME_ENDPOINT})

        PyiCloudPasswordFilter.register(self)
        self._events.subscribe("password_changed", PyiCloudPasswordFilter.on_password_changed)
        # Write Only Props. Changes to apple_id and password will
        # trigger session customization so, set after usinf props
        self.apple_id = apple_id
        self.password = password
        # Prepare Session

    def authenticate(self, force_refresh=False, service=None):
        """
        Handles authentication, and persists cookies so that
        subsequent logins will not cause additional e-mails from Apple.
        """
        LOGGER.debug("Start auth handshake")
        if self._session_data.get("session_token") and not force_refresh:
            try:
                self._validate()
                self._ws = self._state["webservices"]
                LOGGER.debug("Authentication with session token completed successfully")
                return
            except PyiCloudAPIResponseException:
                LOGGER.debug("Invalid authentication token, will log in from scratch.")
                self._session_data.pop("session_token", None)

        login_successful = False
        if service:
            try:
                self._authenticate_setup_service(service)
                login_successful = True
            except Exception:
                LOGGER.debug("Could not log into service. Attempting brand new login.")

        if not login_successful:
            self._authenticate_fetch_session_token()

        self._ws = self._state.get("webservices", {})
        if self._ws:
            LOGGER.debug("Authentication completed successfully")

    def _authenticate_setup_service(self, service):
        """Authenticate to a specific service using credentials."""
        data = {
            "appName": service,
            "apple_id": self.apple_id,
            "password": self._password,
        }
        app = self._state["apps"][service]
        if app.get("canLaunchWithOneFactor", False):
            LOGGER.debug("Authenticating as %s for %s", self.apple_id, service)
            try:
                self._session.post("%s/accountLogin" % self.SETUP_ENDPOINT, data=json.dumps(data))
                self._validate()
            except PyiCloudAPIResponseException as error:
                msg = "Invalid email/password combination."
                self._password = ""
                raise PyiCloudFailedLoginException(msg, error) from error

    def _authenticate_fetch_session_token(self):
        LOGGER.debug("Authenticating as %s", self.apple_id)

        # purge session_token from session_data if exists.
        self._session_data.pop("session_token", None)

        # Prepare Headers
        headers = self._get_auth_headers()
        if self._session_data.get("scnt"):
            headers["scnt"] = self._session_data.get("scnt")
        if self._session_data.get("session_id"):
            headers["X-Apple-ID-Session-Id"] = self._session_data.get("session_id")

        # Prepare content
        data = {"accountName": self.apple_id, "password": self._password, "rememberMe": True, "trustTokens": []}
        if self._session_data.get("trust_token"):
            data["trustTokens"] = [self._session_data.get("trust_token")]

        try:
            self._session.post(
                "%s/signin" % self.AUTH_ENDPOINT,
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
        if not self._session_data.get("session_token"):
            self.password = ""
            return

        self._authenticate_fetch_trust_token()

    def _validate(self):
        """Checks if the current cookie set is still valid."""
        LOGGER.debug("Renewing session using cookies")
        try:
            req = self._session.post("%s/validate" % self.SETUP_ENDPOINT, data="null")
            LOGGER.debug("Session token is still valid")
            self._state = req.json()
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

    def _authenticate_fetch_trust_token(self):
        """Authenticate using session token."""
        data = {
            "accountCountryCode": self._session_data.get("account_country"),
            "dsWebAuthToken": self._session_data.get("session_token"),
            "extended_login": True,
            "trustToken": self._session_data.get("trust_token", ""),
        }
        try:
            req = self._session.post("%s/accountLogin" % self.SETUP_ENDPOINT, data=json.dumps(data))
            self._state = req.json()
        except PyiCloudAPIResponseException as error:
            msg = "Invalid authentication token."
            raise PyiCloudFailedLoginException(msg, error) from error

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
            "X-Apple-OAuth-State": self.config.client_id,
            "X-Apple-Widget-Key": "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d",
        }
        if overrides:
            headers.update(overrides)
        return headers

    def send_verification_code(self, device):
        """Requests that a verification code is sent to the given device."""
        data = json.dumps(device)
        request = self._session.post(
            "%s/sendVerificationCode" % self.SETUP_ENDPOINT,
            params=self.params,
            data=data,
        )
        return request.json().get("success", False)

    def validate_verification_code(self, device, code):
        """Verifies a verification code received on a trusted device."""
        device.update({"verificationCode": code, "trustBrowser": True})
        data = json.dumps(device)

        try:
            self._session.post(
                "%s/validateVerificationCode" % self.SETUP_ENDPOINT,
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

        headers = self._get_auth_headers({"Accept": "application/json"})

        if self._session_data.get("scnt"):
            headers["scnt"] = self._session_data.get("scnt")

        if self._session_data.get("session_id"):
            headers["X-Apple-ID-Session-Id"] = self._session_data.get("session_id")

        try:
            self._session.post(
                "%s/verify/trusteddevice/securitycode" % self.AUTH_ENDPOINT,
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
        headers = self._get_auth_headers()

        if self._session_data.get("scnt"):
            headers["scnt"] = self._session_data.get("scnt")

        if self._session_data.get("session_id"):
            headers["X-Apple-ID-Session-Id"] = self._session_data.get("session_id")

        try:
            self._session.get(
                f"{self.AUTH_ENDPOINT}/2sv/trust",
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
        return self._apple_id

    @apple_id.setter
    def apple_id(self, value):
        if not value:
            raise PyiCloudException("Apple ID cannot be empty")
        if self._apple_id == value:
            return
        if self._apple_id and self._apple_id != value:
            raise PyiCloudException("Apple ID cannot be changed")

        self._apple_id = value
        self._events.fire("apple_id_changed", value)

        # FIXME: Move to event handler
        self._config.apple_id = value

        # Fetch Auth/Session Data now that we have apple_id set
        self._ws = {}
        self._session_data = {}
        try:
            LOGGER.debug("Using session file %s", self._config._session_file)
            with open(self._config._session_file, encoding="utf-8") as f:
                self._session_data = json.load(f)
        except json.JSONDecodeError:
            LOGGER.error("Session file is not a valid JSON file")
        except OSError:
            LOGGER.info("Session file does not exist")

        # Client ID may be stored in global config and session data. Keep it in sync.
        if self._session_data.get("client_id"):
            self.config.client_id = self._session_data.get("client_id")
        self._session_data.update({"client_id": self.config.client_id})
        # Load Cookies
        self._session.load_cookies_from_file(self._config._cookiejar_file)

    @property
    def config(self):
        """Config getter."""
        if self._config is None:
            raise PyiCloudException("Config is not set")
        return self._config.config

    @config.setter
    def config(self, value):
        if not value:
            raise PyiCloudException("Config cannot be empty")
        if self._config == value:
            return
        if self._config and self._config != value:
            raise PyiCloudException("Config cannot be changed")

        self._config = value
        self._events.subscribe("apple_id_changed", lambda id_: setattr(self._config, "apple_id", id_))
        if self.apple_id:
            self._config.apple_id = self.apple_id

    @property
    def password(self):
        """Password getter."""
        raise PyiCloudException("Password is write-only")

    @password.setter
    def password(self, value):
        self._password = value
        self._events.fire("password_changed", value)

    @property
    def session(self):
        """Session getter."""
        if not self._ws:
            raise AttributeError("Session is not authenticated")
        return self._session

    @property
    def state(self):
        """State getter."""
        return self._state

    @property
    def requires_password(self):
        """Returns True if password is required."""
        return self._password == "" and not self._ws

    @property
    def requires_2sa(self):
        """Returns True if two-step authentication is required."""
        return self._state.get("dsInfo", {}).get("hsaVersion", 0) >= 1 and (
            self._state.get("hsaChallengeRequired", False) or not self.is_trusted_session
        )

    @property
    def requires_2fa(self):
        """Returns True if two-factor authentication is required."""
        return self._state["dsInfo"].get("hsaVersion", 0) == 2 and (
            self._state.get("hsaChallengeRequired", False) or not self.is_trusted_session
        )

    @property
    def is_trusted_session(self):
        """Returns True if the session is trusted."""
        return self._state.get("hsaTrustedBrowser", False)

    @property
    def trusted_devices(self):
        """Returns devices trusted for two-step authentication."""
        request = self._session.get("%s/listDevices" % self.SETUP_ENDPOINT, params=self.params)
        return request.json().get("devices")

    def __str__(self):
        return f"iCloud API: {self.apple_id}"

    def __repr__(self):
        return f"<{self}>"


# Alias
PyiCloud = PyiCloudUser


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
            "with_family": self._endpoint.config.with_family,
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
