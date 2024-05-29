"""Library base file."""

from __future__ import annotations

import asyncio
import re
from abc import abstractmethod
from typing import Any

import async_btree as bt

from pyicloud.constants import AppleCookies as Cookie
from pyicloud.constants import AppleHeaders as Header
from pyicloud.exceptions import PyiCloudUserCancelledError
from pyicloud.log import LOGGER
from pyicloud.models.cookies import Cookies
from pyicloud.models.errors import Error
from pyicloud.models.settings import Settings
from pyicloud.sessions.base import BaseResponse
from pyicloud.sessions.login import FreshInit, Init
from pyicloud.sessions.verify_code import VerifyHSA2Code
from pyicloud.trees import BehaveTree, ModelTree, TreeAction


class SetupHooks:
    @abstractmethod
    def get_password(self) -> str: ...

    @abstractmethod
    def get_2fa_code(self, device: Any = None) -> str: ...

    @abstractmethod
    def get_trusted_device(self, devices) -> Any: ...

    # Optional Error hooks
    def on_password_error(self, error: Error): ...

    def on_2fa_code_error(self, error: Error): ...


class SetupModelTree(ModelTree):
    hooks: SetupHooks

    def __init__(self, *, settings: Settings, cookies: Cookies | None = None, hooks: SetupHooks):
        super().__init__(settings=settings, cookies=cookies)
        self.hooks = hooks

    async def is_session_valid(self):
        """Test that we have required session data to operate services without the need to re-authenticate."""
        # Check if we have a valid username
        if not self.settings.account.username:
            LOGGER.debug("No account info found")
            return True
        # Check if we have a valid session token
        if not await self.is_logged_in():
            return True
        # Verify Cookies
        for cookie in self.cookies:
            # Cookie data is too old
            if cookie.is_expired():
                LOGGER.debug(f"Cookie {cookie.key} is expired")
                return True
            # 2FA step not completed yet
            if cookie.key.upper() == Cookie.WEBAUTH_HSA_LOGIN:
                LOGGER.debug(f"Found {Cookie.WEBAUTH_HSA_LOGIN} cookie")
                return True
        return False

    async def reset_config(self):
        """Reset config."""
        LOGGER.debug("Config is in an inconsistent state. Resetting ...")
        self.settings.client_settings.reset_field("scnt")
        self.settings.token.reset_field("session")
        self.settings.token.reset_field("trust")

    async def reset_cookies(self):
        """Reset cookies."""
        LOGGER.debug("Cookies are in an inconsistent state. Resetting ...")
        self.cookies.pop("aasp", None)
        self.cookies.pop("acn01", None)

    @ModelTree.with_context
    @ModelTree.set_context(name="response")
    async def reset_password(self, response: BaseResponse | None = None):
        """
        Check porrevious response and reset password if needed. If no previous
        response or response was unsessecfull, return False
        """
        # If a previous attempt failed, show error...
        if response is not None:
            assert bool(response) is False
            LOGGER.error(f"{response.errors[0].code} ({response.errors[0].message})")
            self.hooks.on_password_error(response.errors[0])
            self.password = None
        return None

    async def is_password_needed(self) -> bool:
        """Check if password is required."""
        # If no password provided. ask for it
        LOGGER.debug(f"Password is needed?: password: '{self.password}'")
        return self.password is None or self.password == ""

    @ModelTree.with_context
    async def ask_password(self):
        # and ask for a new password
        try:
            while not self.password:
                self.password = await asyncio.to_thread(self.hooks.get_password)
                LOGGER.debug(f"Set password to '{self.password}'")
            return True
        except asyncio.exceptions.CancelledError as err:
            LOGGER.debug("Password entry operation stopped by user")
            raise PyiCloudUserCancelledError("Password entry operation stopped by user") from err

    @ModelTree.set_context(name="response")
    async def init(self, refresh=False) -> BaseResponse:
        """Fetch a valid session token."""

        factory = FreshInit if refresh else Init
        # Create a new session
        session = factory(self.settings, self.cookies, client=self.client)
        # Context manager will load and save config and cookies for us
        async with session as client:
            LOGGER.debug(f"Login as '{self.settings.account.username}'")
            await client.send(session.request.model_dump_httpx_request())
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
        if response and Header.TRUST_TOKEN_ELIGIBLE in response.headers:
            LOGGER.debug("2FA is pending")
            return True
        if not self.settings.token.trust:
            LOGGER.debug("No trust token found")
            return True
        if Cookie.WEBAUTH_HSA_LOGIN in self.cookies:
            LOGGER.debug(f"Found {Cookie.WEBAUTH_HSA_LOGIN} cookie")
            return True
        return False

    @ModelTree.set_context(name="response")
    @ModelTree.with_context
    async def reset_security_code(self, response: BaseResponse | None = None):
        """Sign in."""
        # If a previous attempt failed, show error...
        if response is not None and bool(response) is False:
            LOGGER.error(f"{response.errors[0].code} ({response.errors[0].message})")
            self.hooks.on_2fa_code_error(response.errors[0])
        return None

    @ModelTree.set_context(name="security_code")
    async def ask_security_code(self) -> str:
        # and ask for a new password
        while True:
            code = await asyncio.to_thread(self.hooks.get_2fa_code)
            code = re.sub(r"[-_\s]", "", code)
            if re.fullmatch(r"\d{6}", code):
                LOGGER.debug(f"Set security_code to: '{code}'")
                return code

    @ModelTree.set_context(name="response")
    @ModelTree.with_context
    async def complete(self, security_code: str | None = None) -> BaseResponse:
        """Compomete 2FA verification with a valid code"""

        session = VerifyHSA2Code(
            settings=self.settings,
            cookies=self.cookies,
            data={"security_code": security_code},
            client=self.client,
        )

        # Context manager will load and save config and cookies for us
        async with session as complete:
            LOGGER.debug(f"Verifing HSA2 code: '{session.request.body.security_code}'")
            await complete.send(session.request.model_dump_httpx_request())
        # If Sucess, Response will eval to True.
        return session.response


class SetupTree(BehaveTree[SetupModelTree]):
    def _on_error(self, err: Exception) -> tuple[TreeAction, Exception | Any | None]:
        if isinstance(err, PyiCloudUserCancelledError):
            return TreeAction.EXIT, str(err)
        return super()._on_error(err)

    def _setup(self) -> bt.AsyncInnerFunction:
        check_session_subtree = bt.fallback(
            children=[
                bt.inverter(self._model.is_session_valid),
                bt.sequence(
                    children=[
                        bt.always_success(self._model.reset_config),
                        bt.always_success(self._model.reset_cookies),
                    ],
                ),
            ]
        )
        verify_password_subtree = bt.sequence(
            children=[
                bt.fallback(
                    children=[
                        # Check if password is defined. If not, ask for it
                        bt.inverter(self._model.is_password_needed),
                        bt.sequence(
                            children=[
                                # If response is False, there is an error. Show it
                                # reset password and response context
                                bt.always_success(self._model.reset_password),
                                self._model.ask_password,
                            ],
                        ),
                    ]
                ),
                # Try to login
                bt.condition(target=self._model.init, refresh=False),
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
                                # If response is False, there is an error. Show it
                                # and reset response context
                                bt.always_success(self._model.reset_security_code),
                                bt.always_success(self._model.ask_security_code),
                                # If 2FA is needed, verify code
                                self._model.complete,
                            ],
                        ),
                    ]
                ),
            ]
        )

        return bt.sequence(
            children=[
                bt.always_success(check_session_subtree),
                # Login step
                bt.retry(verify_password_subtree, max_retry=3),
                # If Response is true, we sigin was successfull, but a 2FA may be needed
                bt.retry(verify_code_subtree, max_retry=3),
            ]
        )
