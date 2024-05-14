"""Library base file."""

from __future__ import annotations

import asyncio
import getpass
import re
from typing import Any, cast

import async_btree as bt
import httpx

from pyicloud.constants import AppleHeaders as Headers
from pyicloud.exceptions import PyiCloudUserCancelledError
from pyicloud.log import LOGGER, AsyncLogClient
from pyicloud.sessions.base import BaseResponse
from pyicloud.sessions.login import iLogin, iRefreshLogin
from pyicloud.sessions.verify_code import VerifyHSA2Code
from pyicloud.trees import BehaveTree, ModelTree, TreeAction
from pyicloud.utils.decorators import deprecated


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

    async def is_password_needed(self) -> bool:
        """Check if password is required."""
        # If no password provided. ask for it
        LOGGER.debug(f"Password is needed?: password: '{self.password}'")
        return self.password is None or self.password == ""

    @ModelTree.with_context
    async def reset_password_if_needed(self, response: BaseResponse | None = None):
        """
        Check porrevious response and reset password if needed. If no previous
        response or response was unsessecfull, return False
        """
        # If a previous attempt failed, show error...
        if response is not None:
            LOGGER.debug(f"Sign in result:'{bool(response)}'")
            if bool(response) is False:
                LOGGER.error(f"{response.errors[0].code} ({response.errors[0].message})")
                self.password = None
            return bool(response)
        return False

    @ModelTree.with_context
    async def ask_password_if_needed(self):
        # and ask for a new password
        try:
            while not self.password:
                self.password = await asyncio.to_thread(getpass.getpass, "Enter a valid password: ")
                LOGGER.debug(f"Set password to '{self.password}'")
            return True
        except asyncio.exceptions.CancelledError as err:
            LOGGER.debug("Password entry operation stopped by user")
            raise PyiCloudUserCancelledError("Password entry operation stopped by user") from err

    @ModelTree.set_context(name="response")
    async def login(self, refresh=False) -> BaseResponse:
        """Fetch a valid session token."""

        factory = iRefreshLogin if refresh else iLogin
        session = factory(self.settings, self.cookies, client=AsyncLogClient())

        # Context manager will load and save config and cookies for us
        async with session as login:
            LOGGER.debug(f"Login as '{self.settings.account.username}'")
            await login.post(session.ENDPOINT)
        # If Sucess, Response will eval to True.
        return session.response

    async def is_logged_in(self) -> bool:
        """Test that we have required session data to operate services without the need to re-authenticate."""
        if not self.cookies:
            LOGGER.debug("No cookies found")
            return False
        if not self.settings.token.session:
            LOGGER.debug("No session token found")
            return False
        return True

    @ModelTree.with_context
    async def is_2fa_pending(self, response: BaseResponse | None = None) -> int:
        """Return False if a trust token is not present or is not valid anymore."""
        if response and Headers.TRUST_TOKEN_ELIGIBLE in response.headers:
            LOGGER.debug("2FA is pending")
            return True
        if not self.settings.token.trust:
            LOGGER.debug("No trust token found")
            return True
        if "X-APPLE-WEBAUTH-HSA-LOGIN" in self.cookies:
            LOGGER.debug("Found X-APPLE-WEBAUTH-HSA-LOGIN cookie")
            return True
        return True

    @ModelTree.with_context
    async def reset_security_code(self, response: BaseResponse | None):
        """Sign in."""
        # If a previous attempt failed, show error...
        if response is not None:
            LOGGER.debug(f"Sign in result:'{bool(response)}'")
            if bool(response) is False:
                LOGGER.error(f"{response.errors[0].code} ({response.errors[0].message})")
                self.password = None
        return bool(response)

    @ModelTree.set_context(name="security_code")
    async def ask_security_code(self):
        # and ask for a new password
        while True:
            code = await asyncio.to_thread(getpass.getpass, "Enter security_code: ")
            code = re.sub(r"[-_\s]", "", code)
            if re.fullmatch(r"\d{6}", code):
                LOGGER.debug(f"Set security_code to: '{self.password}'")
                return code

    @ModelTree.with_context
    @ModelTree.set_context(name="response")
    async def verify_code(self, verify_code: int) -> BaseResponse:
        """Fetch a valid session token."""

        session = VerifyHSA2Code(self.settings, self.cookies, security_code=verify_code, client=AsyncLogClient())

        # Context manager will load and save config and cookies for us
        async with session as complete:
            LOGGER.debug(f"Verify HSA2 code '{session.request.security_code}'")
            await complete.post(session.ENDPOINT)
        # If Sucess, Response will eval to True.
        return session.response


class SetupTree(BehaveTree[SetupModelTree]):
    def _on_error(self, err: Exception) -> tuple[TreeAction, Exception | Any | None]:
        if isinstance(err, PyiCloudUserCancelledError):
            return TreeAction.EXIT, str(err)
        return super()._on_error(err)

    def _setup(self) -> bt.AsyncInnerFunction:
        verify_password_subtree = bt.sequence(
            children=[
                bt.fallback(
                    children=[
                        # Check if password is defined. If not, ask for it
                        bt.inverter(self._model.is_password_needed),
                        # If response is False, there is an error. Show it and ask new password
                        bt.sequence(
                            children=[
                                self._model.reset_password_if_needed,
                                self._model.ask_password_if_needed,
                            ],
                            succes_threshold=1,
                        ),
                    ]
                ),
                # Try to login
                bt.condition(target=self._model.login, refresh=False),
            ]
        )

        verify_code_subtree = bt.sequence(
            children=[
                self._model.is_logged_in,
                # Check response to see if 2FA is needed A non 0 code is interpreted as False
                bt.fallback(
                    children=[
                        bt.inverter(self._model.is_2fa_pending),
                        bt.sequence(
                            children=[
                                self._model.reset_security_code,
                                self._model.ask_security_code,
                            ],
                            # If reset_security_code is False, ask for a new code
                            succes_threshold=1,
                        ),
                    ]
                ),
                # If 2FA is needed, verify code
                self._model.verify_code,
            ]
        )

        return bt.sequence(
            children=[
                bt.retry(verify_password_subtree, max_retry=3),
                # If Response is true, we sigin was successfull, but a 2FA may be needed
                bt.retry(verify_code_subtree, max_retry=3),
            ]
        )
