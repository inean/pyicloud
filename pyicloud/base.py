"""Library base file."""

from __future__ import annotations

import inspect
import json
import logging
from http import cookiejar
from os import path

from requests import Session
from requests.cookies import cookiejar_from_dict

from pyicloud.config import PyiCloudConfig
from pyicloud.exceptions import (
    PyiCloud2SARequiredException,
    PyiCloudAPIResponseException,
    PyiCloudFailedLoginException,
    PyiCloudServiceNotActivatedException,
)
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

LOGGER = logging.getLogger(__name__)

HEADER_DATA = {
    "X-Apple-ID-Account-Country": "account_country",
    "X-Apple-ID-Session-Id": "session_id",
    "X-Apple-Session-Token": "session_token",
    "X-Apple-TwoSV-Trust-Token": "trust_token",
    "scnt": "scnt",
}


class PyiCloudPasswordFilter(logging.Filter):
    """Password log hider."""

    def __init__(self, password):
        super().__init__(password)

    def filter(self, record):
        message = record.getMessage()
        if self.name in message:
            record.msg = message.replace(self.name, "*" * 8)
            record.args = ()  # Assign an empty tuple instead of an empty list

        return True


class PyiCloudSession(Session):
    """iCloud session."""

    def __init__(self, owner):
        self._owner = owner
        self._state = {}
        super().__init__()

    @property
    def state(self):
        return self._state

    def load_cookies_from_file(self, cookiejar_file):
        lwp_cookie_jar = cookiejar.LWPCookieJar(filename=cookiejar_file)
        try:
            lwp_cookie_jar.load(ignore_discard=True, ignore_expires=True)
            LOGGER.debug("Read cookies from %s", cookiejar_file)
        except FileNotFoundError:
            LOGGER.warning("Failed to read cookiejar %s", cookiejar_file)
        # Convert LWPCookieJar to a dictionary
        cookie_dict = {c.name: c.value for c in lwp_cookie_jar}
        # Create a RequestsCookieJar from the dictionary
        self.cookies = cookiejar_from_dict(cookie_dict)

    def save_cookies_to_file(self, cookiejar_file):
        # Convert RequestsCookieJar to LWPCookieJar
        lwp_cookie_jar = cookiejar.LWPCookieJar()
        for c in self.cookies:
            args = dict(vars(c).items())
            # Convert non standard attributes from RequestsCookieJar to LWPCookieJar
            args["rest"] = args["_rest"]
            args.pop("_rest")
            c = cookiejar.Cookie(**args)
            lwp_cookie_jar.set_cookie(c)
        try:
            # Save LWPCookieJar to file
            LOGGER.debug("Saved cookies to %s", cookiejar_file)
            lwp_cookie_jar.save(filename=cookiejar_file, ignore_discard=True, ignore_expires=True)
        except FileNotFoundError:
            LOGGER.warning("Failed to save cookiejar %s", cookiejar_file)

    def validate(self):
        """Checks if the current cookie set is still valid."""
        LOGGER.debug("Checking session token validity")
        try:
            req = self.post("%s/validate" % PyiCloud.SETUP_ENDPOINT, data="null")
            LOGGER.debug("Session token is still valid")
            self._state = req.json()
        except PyiCloudAPIResponseException as err:
            LOGGER.debug("Invalid authentication token")
            raise err

    def request(self, method, url, **kwargs):  # pylint: disable=arguments-differ
        # Charge logging to the right service endpoint
        callee = inspect.stack()[2]
        module = inspect.getmodule(callee[0])

        logger = logging.getLogger(module.__name__).getChild("http")
        if self._owner.password_filter not in logger.filters:
            logger.addFilter(self._owner.password_filter)
        logger.debug("%s %s %s", method, url, kwargs.get("data", ""))

        has_retried = kwargs.get("retried")
        kwargs.pop("retried", None)
        response = super().request(method, url, **kwargs)

        content_type = response.headers.get("Content-Type", "").split(";")[0]
        json_mimetypes = ["application/json", "text/json"]

        for header, value in HEADER_DATA.items():
            if response.headers.get(header):
                session_arg = value
                self._owner.session_data.update({session_arg: response.headers.get(header)})

        # Save session_data to file
        with open(self._owner.config.session_file, "w", encoding="utf-8") as outfile:
            json.dump(self._owner.session_data, outfile)
            LOGGER.debug("Saved session data to file")

        # Save cookies to file
        self.save_cookies_to_file(self._owner.config.cookiejar_file)

        if not response.ok and (content_type not in json_mimetypes or response.status_code in [421, 450, 500]):
            try:
                # pylint: disable=protected-access
                fmip_url = self._owner["findme"]
                if has_retried is None and response.status_code in [421, 450, 500] and fmip_url in url:
                    # Handle re-authentication for Find My iPhone
                    LOGGER.debug("Re-authenticating Find My iPhone service")
                    try:
                        # If 450, authentication requires a full sign in to the account
                        service = None if response.status_code == 450 else "find"
                        self._owner.authenticate(True, service)

                    except PyiCloudAPIResponseException:
                        LOGGER.debug("Re-authentication failed")
                    kwargs["retried"] = True
                    return self.request(method, url, **kwargs)
            except Exception:
                pass

            if has_retried is None and response.status_code in [421, 450, 500]:
                api_error = PyiCloudAPIResponseException(response.reason, response.status_code, retry=True)
                logger.debug(api_error)
                kwargs["retried"] = True
                return self.request(method, url, **kwargs)

            self._raise_error(response.status_code, response.reason)

        if content_type not in json_mimetypes:
            return response

        try:
            data = response.json()
        except:  # pylint: disable=bare-except
            logger.warning("Failed to parse response with JSON mimetype")
            return response

        logger.debug(data)

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
                self._raise_error(code, reason)

        return response

    def _raise_error(self, code, reason):
        if self._owner.requires_2sa and reason == "Missing X-APPLE-WEBAUTH-TOKEN cookie":
            raise PyiCloud2SARequiredException(self._owner.user["apple_id"])
        if code in ("ZONE_NOT_FOUND", "AUTHENTICATION_FAILED"):
            reason = "Please log into https://icloud.com/ to manually " "finish setting up your iCloud service"
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
        auth_challenge = services.iphone.authenticate(force_refresh=True)
        while wait auth_challenge.err():
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

    def __init__(self, apple_id, config=PyiCloudConfig.from_file()):
        # Public Props
        self.apple_id = apple_id
        self.params = {}

        # Read Only Props
        self._password = ""

        # Private Props
        self._ws = {}
        self._config = config

        # Create a Session
        self._session = PyiCloudSession(self)
        self._session.verify = self._config.verify
        self._session.headers.update({"Origin": self.HOME_ENDPOINT, "Referer": "%s/" % self.HOME_ENDPOINT})

        # Fetch Auth/Session Data
        try:
            LOGGER.debug("Using session file %s", self._config.session_file)
            with open(self._config.session_file, encoding="utf-8") as f:
                self._session_data = json.load(f)
        except OSError:
            LOGGER.info("Session file does not exist")
            self._session_data = {}

        # Client ID may be stored in global config and session data. Keep it in sync.
        if self._session_data.get("client_id"):
            self._config.client_id = self._session_data.get("client_id")
        self._session_data.update({"client_id": self._config.client_id})

        # Load Cookies
        self._session.load_cookies_from_file(self._config.cookiejar_file)

    def authenticate(self, force_refresh=False, service=None):
        """
        Handles authentication, and persists cookies so that
        subsequent logins will not cause additional e-mails from Apple.
        """

        if self._session_data.get("session_token") and not force_refresh:
            LOGGER.debug("Checking session token validity")
            try:
                self._session.validate()
                self._ws = self._session.state["webservices"]
                LOGGER.debug("Authentication with session token completed successfully")
                return
            except PyiCloudAPIResponseException:
                LOGGER.debug("Invalid authentication token, will log in from scratch.")

        if not (login_successful := False) and service:
            try:
                self._authenticate_with_credentials_service(service)
                login_successful = True
            except Exception:
                LOGGER.debug("Could not log into service. Attempting brand new login.")

        if not login_successful:
            self._authenticate_with_crendentials()

        self._ws = self._session.state["webservices"]
        LOGGER.debug("Authentication completed successfully")

    def _authenticate_with_credentials_service(self, service):
        """Authenticate to a specific service using credentials."""
        data = {
            "appName": service,
            "apple_id": self.apple_id,
            "password": self._password,
        }
        app = self._session.state["apps"][service]
        if app.get("canLaunchWithOneFactor", False):
            LOGGER.debug("Authenticating as %s for %s", self.apple_id, service)
        try:
            self._session.post("%s/accountLogin" % self.SETUP_ENDPOINT, data=json.dumps(data))
            self._session.validate()
        except PyiCloudAPIResponseException as error:
            msg = "Invalid email/password combination."
            self._password = ""
            raise PyiCloudFailedLoginException(msg, error) from error

    def _authenticate_with_crendentials(self):
        LOGGER.debug("Authenticating as %s", self.apple_id)

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
            self._password = ""
            raise PyiCloudFailedLoginException(msg, error) from error

        self._authenticate_with_token()

    def _authenticate_with_token(self):
        """Authenticate using session token."""
        data = {
            "accountCountryCode": self._session_data.get("account_country"),
            "dsWebAuthToken": self._session_data.get("session_token"),
            "extended_login": True,
            "trustToken": self._session_data.get("trust_token", ""),
        }
        try:
            self._session.post("%s/accountLogin" % self.SETUP_ENDPOINT, data=json.dumps(data))
            self._session.validate()
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
            "X-Apple-OAuth-State": self._config.client_id,
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
            self._authenticate_with_token()
            return True
        except PyiCloudAPIResponseException:
            LOGGER.error("Session trust failed.")
            return False

    def __getitem__(self, ws_key):
        """Get webservice URL, raise an exception if not exists."""
        if self._ws.get(ws_key) is None:
            raise PyiCloudServiceNotActivatedException("Webservice not available", ws_key)
        return self._ws[ws_key]["url"]

    @property
    def _password(self):
        raise AttributeError("Password is write-only")

    @_password.setter
    def _password(self, value):
        self._password = value
        self._password_filter = PyiCloudPasswordFilter(value)
        LOGGER.addFilter(self._password_filter)

    @property
    def session(self):
        if not self._ws:
            raise AttributeError("Session is not authenticated")
        return self._session

    @property
    def require_password(self):
        """Returns True if password is required."""
        return self._password == ""

    @property
    def requires_2sa(self):
        """Returns True if two-step authentication is required."""
        return self._session.state.get("dsInfo", {}).get("hsaVersion", 0) >= 1 and (
            self._session.state.get("hsaChallengeRequired", False) or not self.is_trusted_session
        )

    @property
    def requires_2fa(self):
        """Returns True if two-factor authentication is required."""
        return self._session.state["dsInfo"].get("hsaVersion", 0) == 2 and (
            self._session.state.get("hsaChallengeRequired", False) or not self.is_trusted_session
        )

    @property
    def is_trusted_session(self):
        """Returns True if the session is trusted."""
        return self._session.state.get("hsaTrustedBrowser", False)

    @property
    def trusted_devices(self):
        """Returns devices trusted for two-step authentication."""
        request = self._session.get("%s/listDevices" % self.SETUP_ENDPOINT, params=self._params)
        return request.json().get("devices")

    def __str__(self):
        return f"iCloud API: {self.apple_id}"

    def __repr__(self):
        return f"<{self}>"


class PyiCloudServices:
    """
    A base authentication class for the iCloud service. Handles the
    authentication required to access iCloud services.

    Usage:
        from pyicloud import PyiCloudService
        pyicloud = PyiCloudService('username@apple.com', 'password')
        pyicloud.iphone.location()
    """

    def __init__(self, endpoint):
        self._endpoint = endpoint
        # Expensive services
        self._drive = None
        self._photos = None
        self._files = None

    @property
    def devices(self):
        """Returns all devices."""
        kwargs = {
            "service_root": self._endpoint["findme"],
            "session": self._endpoint.session,
            "params": self._endpoint.params,
            "with_family": self._endpoint.config.with_family,
        }
        return FindMyiPhoneServiceManager(**kwargs)

    @property
    def iphone(self):
        """Returns the iPhone."""
        return self.devices[0]

    @property
    def account(self):
        """Gets the 'Account' service."""
        kwargs = {
            "service_root": self._endpoint["account"],
            "session": self._endpoint.session,
            "params": self._endpoint.params,
        }
        return AccountService(**kwargs)

    @property
    def files(self):
        """Gets the 'File' service."""
        if not self._files:
            kwargs = {
                "service_root": self._endpoint["ubiquity"],
                "session": self._endpoint.session,
                "params": self._endpoint.params,
            }
            self._files = UbiquityService(**kwargs)
        return self._files

    @property
    def photos(self):
        """Gets the 'Photo' service."""
        if not self._photos:
            kwargs = {
                "service_root": self._endpoint["ckdatabasews"],
                "session": self._endpoint.session,
                "params": self._endpoint.params,
            }
            self._photos = PhotosService(**kwargs)
        return self._photos

    @property
    def calendar(self):
        """Gets the 'Calendar' service."""
        kwargs = {
            "service_root": self._endpoint["calendar"],
            "session": self._endpoint.session,
            "params": self._endpoint.params,
        }
        return CalendarService(**kwargs)

    @property
    def contacts(self):
        """Gets the 'Contacts' service."""
        kwargs = {
            "service_root": self._endpoint["contacts"],
            "session": self._endpoint.session,
            "params": self._endpoint.params,
        }
        return ContactsService(**kwargs)

    @property
    def reminders(self):
        """Gets the 'Reminders' service."""
        kwargs = {
            "service_root": self._endpoint["reminders"],
            "session": self._endpoint.session,
            "params": self._endpoint.params,
        }
        return RemindersService(**kwargs)

    @property
    def drive(self):
        """Gets the 'Drive' service."""
        if not self._drive:
            kwargs = {
                "service_root": self._endpoint["drivews"],
                "document_root": self._endpoint["docws"],
                "session": self._endpoint.session,
                "params": self._endpoint.params,
            }
            self._drive = DriveService(**kwargs)
        return self._drive

    def __str__(self):
        return f"iCloudFactory API: {self._endpoint.apple_id}"

    def __repr__(self):
        return f"<{self}>"


class PyiCloudService:
    """
    A base authentication class for the iCloud service. Handles the
    authentication required to access iCloud services.

    Usage:
        from pyicloud import PyiCloudService
        pyicloud = PyiCloudService('username@apple.com', 'password')
        pyicloud.iphone.location()
    """

    AUTH_ENDPOINT = "https://idmsa.apple.com/appleauth/auth"
    HOME_ENDPOINT = "https://www.icloud.com"
    SETUP_ENDPOINT = "https://setup.icloud.com/setup/ws/1"

    # FIXME: If apple_id and password are not provided, ignore cookies and session stuff
    # FIXME: if apple_id is missig, take default oine from config file
    def __init__(self, apple_id=None, password=None, config=None):
        self.config = config or PyiCloudConfig.from_file()
        self.config.apple_id = apple_id or self.config.apple_id

        self.user = {"accountName": apple_id or self.config.apple_id, "password": password}
        self.client_id = self.config.client_id
        self.with_family = self.config.with_family

        self.data = {}  # Make protected?
        self.params = {}  # Make protected?
        self.session_data = {}  # Make protected?

        self._cookie_dir = None
        self._session_dir = None

        self.password_filter = PyiCloudPasswordFilter(password)
        LOGGER.addFilter(self.password_filter)

        self.session_data = {}
        try:
            LOGGER.debug("Using session file %s", self.config.session_file)
            with open(self.config.session_file, encoding="utf-8") as session_f:
                self.session_data = json.load(session_f)
        except:  # pylint: disable=bare-except
            LOGGER.info("Session file does not exist")

        if self.session_data.get("client_id"):
            self.client_id = self.session_data.get("client_id")
        else:
            self.session_data.update({"client_id": self.client_id})

        self.session = PyiCloudSession(self)
        self.session.verify = self.config.verify
        self.session.headers.update({"Origin": self.HOME_ENDPOINT, "Referer": "%s/" % self.HOME_ENDPOINT})

        cookiejar_path = self.config.cookiejar_file
        self.session.cookies = cookiejar.LWPCookieJar(filename=cookiejar_path)
        if path.exists(cookiejar_path):
            try:
                self.session.cookies.load(ignore_discard=True, ignore_expires=True)
                LOGGER.debug("Read cookies from %s", cookiejar_path)
            except:  # pylint: disable=bare-except
                # Most likely a pickled cookiejar from earlier versions.
                # The cookiejar will get replaced with a valid one after
                # successful authentication.
                LOGGER.warning("Failed to read cookiejar %s", cookiejar_path)

        self.authenticate()

        self._drive = None
        self._files = None
        self._photos = None

    def authenticate(self, force_refresh=False, service=None):
        """
        Handles authentication, and persists cookies so that
        subsequent logins will not cause additional e-mails from Apple.
        """

        if self.session_data.get("session_token") and not force_refresh:
            LOGGER.debug("Checking session token validity")
            try:
                self.data = self._validate_token()
                self._webservices = self.data["webservices"]
                LOGGER.debug("Authentication with session token completed successfully")
                return
            except PyiCloudAPIResponseException:
                LOGGER.debug("Invalid authentication token, will log in from scratch.")

        login_successful = False
        if not login_successful and service is not None:
            app = self.data["apps"][service]
            if "canLaunchWithOneFactor" in app and app["canLaunchWithOneFactor"]:
                LOGGER.debug("Authenticating as %s for %s", self.user["accountName"], service)
                try:
                    self._authenticate_with_credentials_service(service)
                    login_successful = True
                except Exception:
                    LOGGER.debug("Could not log into service. Attempting brand new login.")

        if not login_successful:
            LOGGER.debug("Authenticating as %s", self.user["accountName"])

            data = dict(self.user)

            data["rememberMe"] = True
            data["trustTokens"] = []
            if self.session_data.get("trust_token"):
                data["trustTokens"] = [self.session_data.get("trust_token")]

            headers = self._get_auth_headers()

            if self.session_data.get("scnt"):
                headers["scnt"] = self.session_data.get("scnt")

            if self.session_data.get("session_id"):
                headers["X-Apple-ID-Session-Id"] = self.session_data.get("session_id")

            try:
                self.session.post(
                    "%s/signin" % self.AUTH_ENDPOINT,
                    params={"isRememberMeEnabled": "true"},
                    data=json.dumps(data),
                    headers=headers,
                )
            except PyiCloudAPIResponseException as error:
                msg = "Invalid email/password combination."
                raise PyiCloudFailedLoginException(msg, error) from error

            self._authenticate_with_token()

        self._webservices = self.data["webservices"]

        LOGGER.debug("Authentication completed successfully")

    def _authenticate_with_token(self):
        """Authenticate using session token."""
        data = {
            "accountCountryCode": self.session_data.get("account_country"),
            "dsWebAuthToken": self.session_data.get("session_token"),
            "extended_login": True,
            "trustToken": self.session_data.get("trust_token", ""),
        }

        try:
            req = self.session.post("%s/accountLogin" % self.SETUP_ENDPOINT, data=json.dumps(data))
            self.data = req.json()
        except PyiCloudAPIResponseException as error:
            msg = "Invalid authentication token."
            raise PyiCloudFailedLoginException(msg, error) from error

    def _authenticate_with_credentials_service(self, service):
        """Authenticate to a specific service using credentials."""
        data = {
            "appName": service,
            "apple_id": self.user["accountName"],
            "password": self.user["password"],
        }

        try:
            self.session.post("%s/accountLogin" % self.SETUP_ENDPOINT, data=json.dumps(data))

            self.data = self._validate_token()
        except PyiCloudAPIResponseException as error:
            msg = "Invalid email/password combination."
            raise PyiCloudFailedLoginException(msg, error) from error

    def _validate_token(self):
        """Checks if the current access token is still valid."""
        LOGGER.debug("Checking session token validity")
        try:
            req = self.session.post("%s/validate" % self.SETUP_ENDPOINT, data="null")
            LOGGER.debug("Session token is still valid")
            return req.json()
        except PyiCloudAPIResponseException as err:
            LOGGER.debug("Invalid authentication token")
            raise err

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
            "X-Apple-OAuth-State": self.client_id,
            "X-Apple-Widget-Key": "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d",
        }
        if overrides:
            headers.update(overrides)
        return headers

    @property
    def requires_2sa(self):
        """Returns True if two-step authentication is required."""
        return self.data.get("dsInfo", {}).get("hsaVersion", 0) >= 1 and (
            self.data.get("hsaChallengeRequired", False) or not self.is_trusted_session
        )

    @property
    def requires_2fa(self):
        """Returns True if two-factor authentication is required."""
        return self.data["dsInfo"].get("hsaVersion", 0) == 2 and (
            self.data.get("hsaChallengeRequired", False) or not self.is_trusted_session
        )

    @property
    def is_trusted_session(self):
        """Returns True if the session is trusted."""
        return self.data.get("hsaTrustedBrowser", False)

    @property
    def trusted_devices(self):
        """Returns devices trusted for two-step authentication."""
        request = self.session.get("%s/listDevices" % self.SETUP_ENDPOINT, params=self.params)
        return request.json().get("devices")

    def send_verification_code(self, device):
        """Requests that a verification code is sent to the given device."""
        data = json.dumps(device)
        request = self.session.post(
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
            self.session.post(
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

        if self.session_data.get("scnt"):
            headers["scnt"] = self.session_data.get("scnt")

        if self.session_data.get("session_id"):
            headers["X-Apple-ID-Session-Id"] = self.session_data.get("session_id")

        try:
            self.session.post(
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

        if self.session_data.get("scnt"):
            headers["scnt"] = self.session_data.get("scnt")

        if self.session_data.get("session_id"):
            headers["X-Apple-ID-Session-Id"] = self.session_data.get("session_id")

        try:
            self.session.get(
                f"{self.AUTH_ENDPOINT}/2sv/trust",
                headers=headers,
            )
            self._authenticate_with_token()
            return True
        except PyiCloudAPIResponseException:
            LOGGER.error("Session trust failed.")
            return False

    def _get_webservice_url(self, ws_key):
        """Get webservice URL, raise an exception if not exists."""
        if self._webservices.get(ws_key) is None:
            raise PyiCloudServiceNotActivatedException("Webservice not available", ws_key)
        return self._webservices[ws_key]["url"]

    @property
    def devices(self):
        """Returns all devices."""
        service_root = self._get_webservice_url("findme")
        return FindMyiPhoneServiceManager(service_root, self.session, self.params, self.with_family)

    @property
    def iphone(self):
        """Returns the iPhone."""
        return self.devices[0]

    @property
    def account(self):
        """Gets the 'Account' service."""
        service_root = self._get_webservice_url("account")
        return AccountService(service_root, self.session, self.params)

    @property
    def files(self):
        """Gets the 'File' service."""
        if not self._files:
            service_root = self._get_webservice_url("ubiquity")
            self._files = UbiquityService(service_root, self.session, self.params)
        return self._files

    @property
    def photos(self):
        """Gets the 'Photo' service."""
        if not self._photos:
            service_root = self._get_webservice_url("ckdatabasews")
            self._photos = PhotosService(service_root, self.session, self.params)
        return self._photos

    @property
    def calendar(self):
        """Gets the 'Calendar' service."""
        service_root = self._get_webservice_url("calendar")
        return CalendarService(service_root, self.session, self.params)

    @property
    def contacts(self):
        """Gets the 'Contacts' service."""
        service_root = self._get_webservice_url("contacts")
        return ContactsService(service_root, self.session, self.params)

    @property
    def reminders(self):
        """Gets the 'Reminders' service."""
        service_root = self._get_webservice_url("reminders")
        return RemindersService(service_root, self.session, self.params)

    @property
    def drive(self):
        """Gets the 'Drive' service."""
        if not self._drive:
            self._drive = DriveService(
                service_root=self._get_webservice_url("drivews"),
                document_root=self._get_webservice_url("docws"),
                session=self.session,
                params=self.params,
            )
        return self._drive

    def __str__(self):
        return f"iCloud API: {self.user.get('apple_id')}"

    def __repr__(self):
        return f"<{self}>"
