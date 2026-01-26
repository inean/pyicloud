"""Library base file."""

from __future__ import annotations

import asyncio
from functools import partial
import re
from abc import abstractmethod
from collections.abc import Sequence
from typing import Any, cast

import async_btree as bt

from pyicloud.constants import AppleCookies as Cookie
from pyicloud.constants import AppleHeaders as Header
from pyicloud.exceptions import PyiCloudUserCancelledError
from pyicloud.log import LOGGER
from pyicloud.models.cookies import Cookies
from pyicloud.models.errors import Error
from pyicloud.models.settings import Settings
from pyicloud.sessions import BaseResponse
from pyicloud.sessions.account_login import AccountLogin
from pyicloud.sessions.security_code import SecurityCode
from pyicloud.sessions.signin import FreshSignIn, SignIn
from pyicloud.sessions.trust import Trust
from pyicloud.trees import TreeState, TreeTransitionExtra, blackboard, use_blackboard
from pyicloud.trees.session import SessionModelTree


class SetupHooks:
    @abstractmethod
    def get_password(self, username: str) -> str: ...

    @abstractmethod
    def get_security_code(self, device: Any = None) -> str: ...

    @abstractmethod
    def get_trusted_device(self, devices) -> Any: ...

    # Optional Error hooks
    def on_password_error(self, error: Error): ...

    def on_security_code_error(self, error: Error): ...


class SetupModelTree(SessionModelTree):
    hooks: SetupHooks

    def __init__(
        self,
        *,
        settings: Settings,
        cookies: Cookies | None = None,
        hooks: SetupHooks,
        context: dict[str, Any] | None = None,
    ):
        super().__init__(settings=settings, cookies=cookies, context=context)
        self.hooks = hooks

    @blackboard(fetch=True, store="response")
    async def password_reset_if_needed(self, response: BaseResponse | None = None):
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

    async def password_is_needed(self) -> bool:
        """Check if password is required."""
        # If no password provided. ask for it
        LOGGER.debug(f"Password is needed?: password: '{self.password}'")
        return self.password is None or self.password == ""

    @use_blackboard
    async def password_ask(self):
        # and ask for a new password
        try:
            while not self.password:
                self.password = await asyncio.to_thread(partial(self.hooks.get_password, self.username))
                LOGGER.debug(f"Set password to '{self.password}'")
            return True
        except asyncio.exceptions.CancelledError as err:
            LOGGER.debug("Password entry operation stopped by user")
            raise PyiCloudUserCancelledError("Password entry operation stopped by user") from err

    @blackboard(fetch=True, store="response")
    async def signin(self, refresh_signin=True) -> BaseResponse:
        """Fetch a valid session token."""

        factory = FreshSignIn
        if not self.settings.client_settings.scnt:
            LOGGER.debug(f"No {Header.SCNT} found")
            factory = SignIn
        if not self.settings.account.session_id:
            LOGGER.debug(f"No {Header.SESSION_ID} found")
        if refresh_signin is False:
            LOGGER.debug("Sigin with new session id")
            factory = SignIn

        # Create a new session
        session = factory(self.settings, self.cookies, client=self.client)
        # Context manager will load and save config and cookies for us
        async with session as client:
            LOGGER.debug(f"Login as '{self.settings.account.username}'")
            await client.send(session.request.create_request())
        # If Sucess, Response will eval to True.
        return session.response

    async def security_code_are_preconditions_met(self) -> bool:
        """We are logged when have all required cookies and headers to perform 2FA step"""

        # FIXME: Fetch Cookie names from SecurityCode.cookies.request
        if not self.cookies:
            LOGGER.debug("No cookies found")
            return False
        if Cookie.ACN01 not in self.cookies:
            LOGGER.debug(f"No {Cookie.ACN01} cookie found")
            return False
        if Cookie.AASP not in self.cookies:
            LOGGER.debug(f"No {Cookie.AASP} cookie found")
            return False

        # FIXME: Fetch Header names from SecurityCode.headers.request
        if not self.settings.client_settings.scnt:
            LOGGER.debug("No SCNT found")
            return False
        if not self.settings.account.session_id:
            LOGGER.debug("No session token found")
            return False
        return True

    @use_blackboard
    async def is_security_code_required(self, response: BaseResponse | None = None) -> int:
        """Return False if a trust token is not present or is not valid anymore."""
        if response and Header.TRUST_TOKEN_ELIGIBLE in response.headers:
            LOGGER.debug("2FA is pending")
            return True
        if self.settings.client_settings.trust_eligible and not self.settings.token.trust:
            LOGGER.debug("Missing session token for a 2FA account")
            return True
        return False

    @blackboard(fetch=True, remove="response")
    async def security_code_reset(self, response: BaseResponse | None = None):
        if response is None or bool(response):
            # No error -> No need to reset
            return False
        # If a previous attempt failed, show error...
        error = response.errors.pop(0)
        # Pop security code from blackboard if exists
        LOGGER.debug(f"Resetting security code: '{error.message}' ({error.code})")
        self.blackboard.pop("security_code", None)
        # Call error hook
        self.hooks.on_security_code_error(error)
        return True

    @blackboard(fetch=True, store="security_code")
    async def security_code_ask(self, security_code: str = "") -> str:
        # Validate
        while not re.fullmatch(r"\d{6}", security_code):
            # and ask for a new password
            security_code = await asyncio.to_thread(self.hooks.get_security_code)
            security_code = re.sub(r"[-_\s]", "", security_code)
        # Store on blackboard
        LOGGER.debug(f"Set security_code to: '{security_code}'")
        return security_code

    @blackboard(fetch=True)
    async def security_code(self, security_code: str) -> BaseResponse:
        """Compomete 2FA verification with a valid code"""
        data = {"security_code": security_code}
        session = SecurityCode(settings=self.settings, cookies=self.cookies, data=data, client=self.client)
        async with session as complete:
            LOGGER.debug(f"Verifing HSA2 code: '{session.request.body.security_code}'")
            await complete.send(session.request.create_request())
        return session.response

    async def trust(self) -> BaseResponse:
        """Trust the session."""
        assert self.settings.token.session, "Session token is required to trust the session."
        session = Trust(settings=self.settings, cookies=self.cookies, client=self.client)
        async with session as complete:
            LOGGER.debug(f"Trust session with: '{self.settings.token.session[:7]}...'")
            await complete.send(session.request.create_request())
        return session.response

    async def account_login(self, require_trust_token=True) -> BaseResponse:
        """Fetch account login."""
        if require_trust_token and not self.settings.token.trust:
            raise ValueError("Trust token is required to fetch account login.")
        session = AccountLogin(settings=self.settings, cookies=self.cookies, client=self.client)
        async with session as complete:
            LOGGER.debug(f"Fetch account details for: '{self.settings.account.username}'")
            await complete.send(session.request.create_request())
        return session.response

    @property
    def transitions(self) -> Sequence[TreeTransitionExtra]:
        return [
            cast(
                TreeTransitionExtra,
                {
                    "trigger": "signin",
                    "source": TreeState.SESSION_CLOSED,
                    "dest": TreeState.SESSION_LOGGED,
                    "action": self.run,
                },
            )
        ] + list(super().transitions)

    @property
    def bhtree(self) -> bt.AsyncInnerFunction:
        signin_subtree = bt.sequence(
            children=[
                # If response is present and False, there is an error. Show it and
                # reset password and response context
                bt.always_success(self.password_reset_if_needed),
                bt.fallback(
                    children=[
                        # Check if password is defined. If not, ask for it
                        bt.inverter(self.password_is_needed),
                        self.password_ask,
                    ]
                ),
                # Try to login
                bt.fallback(
                    children=[
                        bt.condition(target=self.signin),
                        bt.sequence(
                            children=[
                                bt.always_success(self._session_reset_config),
                                bt.always_success(self._session_reset_cookies),
                            ],
                        ),
                    ]
                ),
            ]
        )

        security_code_subtree = bt.fallback(
            children=[
                # Check response to see if 2FA is needed. A non 0 code is interpreted as False
                bt.inverter(self.is_security_code_required),
                bt.sequence(
                    children=[
                        self.security_code_are_preconditions_met,
                        # If response is False, there is an error. Show it
                        # and reset response context
                        bt.always_success(self.security_code_reset),
                        bt.always_success(self.security_code_ask),
                        # If 2FA is needed, verify code
                        self.security_code,
                        # Trust session code,
                        self.trust,
                    ],
                ),
            ]
        )

        account_login_subtree = bt.sequence(
            children=[
                # Get Account Login,
                bt.action(self.account_login, require_trust_token=True),
                # Validate response to ensure we are logged in
                self._session_is_valid,
            ]
        )

        return bt.fallback(
            children=[
                self._session_is_valid,
                bt.sequence(
                    children=[
                        # Login step
                        bt.retry(signin_subtree, max_retry=3),
                        # If Response is true, we sigin was successfull, but a 2FA may be needed
                        bt.retry(security_code_subtree, max_retry=3),
                        # Fetch Acccount login.
                        bt.action(account_login_subtree),
                    ],
                ),
            ],
        )
