"""Library base file."""

from __future__ import annotations

import contextvars
import getpass
from abc import abstractmethod
from functools import partial, wraps
from typing import Any, cast

import anyio
import anyio.to_thread
import async_btree as bt
import httpx
from psygnal.containers import EventedDict

from pyicloud.exceptions import (
    PyiCloudException,
)
from pyicloud.log import LOGGER, AsyncLogClient, PyiCloudPasswordFilter
from pyicloud.models.cookies import Cookies
from pyicloud.models.settings import Settings
from pyicloud.paths import CookiesJar, SettingsFile
from pyicloud.sessions.base import BaseResponse
from pyicloud.sessions.httpx import iAsyncClient
from pyicloud.sessions.login import iLogin, iRefreshLogin
from pyicloud.utils.decorators import deprecated


class iModel:
    _config: Settings

    def __init__(self, config: Settings):
        self.settings = config

    @deprecated
    async def _session_is_logged_in(self):
        """Test that we have required session data to operate services without the need to re-authenticate."""
        print("Session is signed")
        if not self.cookies:
            LOGGER.debug("No cookies found")
            return False
        if not self._config.token.session:
            LOGGER.debug("No session token found")
            return False
        return True

    #   // Now, validate the session with checking for important aspects that show that the session can be used to get data (e.g. there need to be a token, some cookies and account info)
    #   self.loggedIn = (function() {
    #     //console.log(self.auth.cookies.length > 0, !!self.auth.token, Object.keys(self.account).length > 0, self.username === username);
    #     return ((self.auth.cookies.length > 0) && (self.auth.token && Object.keys(self.account).length > 0) && (username ? (self.username === username) : false));
    #   })();

    # self.cookiesValid = (function() {
    #      const timestamp = new Date().getTime();
    #      // Get list of cookies, represented to a boolean value wether the cookie is expired or no
    #      // ignore cookie wich is expiring in 1970 --> so no extra code auth, when starting app
    #      const cookiesExpired = self.auth.cookies.map(function (cookie) {
    #        if ('X-APPLE-WEBAUTH-HSA-LOGIN' in cookie && 'Expires' in cookie) {
    #          return false;
    #        } else {
    #          return new Date(cookie.Expires).getTime() - timestamp < 0;
    #        }
    #      });
    #      // If no cookie is expired, the array contains just 'false' keys
    #      // Return wether there is no expired cookie (true)
    #      return cookiesExpired.indexOf(true) === -1;
    #   })();

    @deprecated
    async def _session_is_2fa_pending(self):
        """Return False if a trust token is not present or is not valid anymore."""
        if not self._config.token.trust:
            LOGGER.debug("No trust token found")
            return True
        if "X-APPLE-WEBAUTH-HSA-LOGIN" in self.cookies:
            LOGGER.debug("Found X-APPLE-WEBAUTH-HSA-LOGIN cookie")
            return True
        return True

    @deprecated
    async def _session_is_expired(self):
        """Test that we have required session data to operate services without the need to re-authenticate."""
        if not await self._session_is_logged_in():
            return True
        if not self._config["account"]:
            LOGGER.debug("No account info found")
            return True
        # Verify Cookies
        for cookie in cast(httpx.Cookies, self.cookies).jar:
            # 2FA step not completed yet
            if cookie.name == "X-APPLE-WEBAUTH-HSA-LOGIN":
                LOGGER.debug("Found X-APPLE-WEBAUTH-HSA-LOGIN cookie")
                return True
            # Cookie data is too old
            if cookie.is_expired():
                LOGGER.debug(f"Cookie {cookie.name} is expired")
                return True
        return False

    @deprecated
    async def _session_renew(self):
        """Renew session data."""
        print("Renew session")

    async def login(self, username: str = "", password: str = "", refresh=False) -> BaseResponse:
        """Fetch a valid session token."""
        factory = iRefreshLogin if refresh else iLogin
        session = factory(self.settings, self.cookies, client=AsyncLogClient())

        # Context manager will load and save config and cookies for us
        async with session as login:
            LOGGER.debug(f"Fresh Login as '{username or self.settings['account.username']}'")
            # Prepare data object to post with login info
            _ = username and cast(iAsyncClient, login).json_data.update({"username": username})
            _ = password and cast(iAsyncClient, login).json_data.update({"password": password})
            # post
            await login.post(session.ENDPOINT, json=cast(iAsyncClient, login).json_data)
            # If Sucess, Response will eval to True.
            return session.response

    async def is_password_needed(self) -> bool:
        """Check if password is required."""
        # If no password provided. ask for it
        LOGGER.debug(f"Password is needed?: password: '{self.password}'")
        return self.password is None or self.password == ""

    async def on_signin(self, response: BaseResponse | None = None):
        """Sign in."""
        # If a previous attempt failed, show error...
        LOGGER.debug(f"Sign in result:'{bool(response)}'")
        if response and bool(response) is False:
            print(f"{response.errors[0].code} ({response.errors[0].message})")
        # and ask for a new password
        password = self.settings["account.password"]
        while not password:
            password = await anyio.to_thread.run_sync(getpass.getpass, "Enter a valid password: ")
            self.settings["account.password"] = password
        LOGGER.debug(f"Set password to '{self.settings['account.password']}'")

    @property
    def settings(self) -> Settings:
        """Config getter."""
        return self._config

    @settings.setter
    def settings(self, value: Settings):
        assert isinstance(value, Settings)

        # Sanity checks
        if self._config == value:
            return
        if self._config and self._config != value:
            raise PyiCloudException("Config cannot be changed")

        # Set new config
        self._config = value

        # Add a filter so password is not logged
        PyiCloudPasswordFilter.register(self.settings)
        self.settings.account.events.password.connect(
            partial(PyiCloudPasswordFilter.on_changed_password, context=self.settings)
        )

        # Listen to username updates and reload config if necessary
        self.settings.account.events.username.connect(partial(SettingsFile(self.settings).loads))
        self.settings.account.events.username.emit()

    @property
    def cookies(self) -> Cookies:
        """Cookies getter."""
        if self._cookies is None:
            self._cookies = Cookies(EventedDict())
            if self.apple_id:
                jar = CookiesJar(self._cookies)
                jar.loads(username=self.apple_id)
            # Connect to signal to update/refresh cookies when username changes
            self.settings.account.events.username.connect(lambda username: jar.loads(username=username))
        return self._cookies

    @property
    def apple_id(self) -> str:
        """Apple ID getter."""
        return self.settings.account.username

    @property
    def password(self) -> str | None:
        """Password getter."""
        password = self.settings.account.password
        return password.get_secret_value() if password else None

    @password.setter
    def password(self, value):
        self.settings.account.password = value

    def __str__(self):
        return f"iCloud API: {self.apple_id}"

    def __repr__(self):
        return f"<{self}>"


class iBehaveTree(bt.BTreeRunner):
    def __init__(self, model: iModel, **kwargs):
        bt.BTreeRunner.__init__(self, **kwargs)
        self._model = model
        self._btree: bt.AsyncInnerFunction | None = None
        self._cache: dict[str, Any] = {}

    def __enter__(self):
        self._cache = {}
        self._btree = self._setup()
        return super().__enter__()

    def __exit__(self, exc_type, exc, tb):
        super().__exit__(exc_type, exc, tb)
        self._btree = None
        self._cache = {}

    def run(self):
        assert self._btree is not None, "Tree is not setup"
        return bt.BTreeRunner.run(self, self._btree)

    def analyze(self, indent: int = 0, label: str | None = None) -> str:
        if self._btree is None:
            return f"--> {label or 'root'}:"
        return bt.stringify_analyze(bt.analyze(self._btree), indent, label)

    def pull(self, name: str):
        """Store response in context."""

        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                result = await func(*args, **kwargs)
                self._cache[name] = result
                return result

            return wrapper

        return decorator

    def push(self, name: str):
        """Pass variable from context as a keyword argument to func."""

        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                kwargs[name] = self._cache.get(name)
                result = await func(*args, **kwargs)
                return result

            return wrapper

        return decorator

    @abstractmethod
    def _setup(self):
        assert not self._btree, "Tree already setup"

    @property
    def tree(self):
        assert self._btree, "Tree is not setup"
        return self._btree


class iSetupTree(iBehaveTree):
    response_var = contextvars.ContextVar("response")

    def _setup(self):
        self.response_var.set(None)

        return bt.retry(
            bt.sequence(
                children=[
                    bt.retry(
                        bt.fallback(
                            children=[
                                # Check if password is defined. If not, ask for it
                                bt.condition(target=bt.inverter(self._model.is_password_needed)),
                                # If response is False, there is an error. Show it and ask new password
                                bt.always_success(bt.condition(target=self.push("response")(self._model.on_signin))),
                            ]
                        ),
                        max_retry=2,
                    ),
                    # Try to login
                    bt.fallback(
                        children=[
                            # Check response status. 401 means password is invalid and bool(response) is False
                            bt.condition(target=self.pull("response")(self._model.login), refresh=False),
                            # Reset password and retry sequence again
                            bt.always_failure(lambda: setattr(self._model, "password", None)),
                        ]
                    ),
                ]
            ),
            max_retry=2,
        )


class iRenewTree(iBehaveTree):
    def _setup(self):
        return bt.sequence(
            children=[
                bt.condition(self._model._session_is_logged_in),
                bt.condition(bt.inverter(self._model._session_is_2fa_pending)),
                bt.condition(bt.inverter(self._model._session_is_expired)),
                bt.always_success(child=self._model._session_renew),
            ]
        )


class iSessionTree(iBehaveTree):
    def setup_leafs(self):
        raise NotImplementedError
