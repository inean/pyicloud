"""Library base file."""

from __future__ import annotations

import contextvars
import getpass
from typing import cast

import anyio
import anyio.to_thread
import async_btree as bt
import httpx

from pyicloud.log import LOGGER, AsyncLogClient
from pyicloud.sessions.base import BaseResponse
from pyicloud.sessions.httpx import iAsyncClient
from pyicloud.sessions.login import iLogin, iRefreshLogin
from pyicloud.utils.decorators import deprecated

from .base import BehaveTree, ModelTree


class SetupModelTree(ModelTree):
    @deprecated
    async def _session_is_logged_in(self):
        """Test that we have required session data to operate services without the need to re-authenticate."""
        print("Session is signed")
        if not self.cookies:
            LOGGER.debug("No cookies found")
            return False
        if not self.settings.token.session:
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
        if not self.settings.token.trust:
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
        if not self.settings.account.username:
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


class SetupTree(BehaveTree[SetupModelTree]):
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
