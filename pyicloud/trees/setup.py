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
from pyicloud.models import Meta
from pyicloud.models.cookies import Cookies
from pyicloud.models.errors import Error
from pyicloud.models.settings import Settings
from pyicloud.sessions import BaseResponse
from pyicloud.sessions.account_login import AccountLogin, AccountLoginResponseCookies
from pyicloud.sessions.security_code import SecurityCode
from pyicloud.sessions.signin import FreshSignIn, SignIn
from pyicloud.sessions.trust import Trust
from pyicloud.trees import BehaveTree, ModelTree, TreeAction


class SetupHooks:
    @abstractmethod
    def get_password(self) -> str: ...

    @abstractmethod
    def get_security_code(self, device: Any = None) -> str: ...

    @abstractmethod
    def get_trusted_device(self, devices) -> Any: ...

    # Optional Error hooks
    def on_password_error(self, error: Error): ...

    def on_security_code_error(self, error: Error): ...


class SetupModelTree(ModelTree):
    hooks: SetupHooks

    def __init__(self, *, settings: Settings, cookies: Cookies | None = None, hooks: SetupHooks):
        super().__init__(settings=settings, cookies=cookies)
        self.hooks = hooks

    async def session_is_valid(self):
        """Test that we have required session data to operate services without the need to re-authenticate."""
        # Check if we have a valid username
        if not self.settings.account.username:
            LOGGER.debug("No account info found")
            return False
        # Check if we have a valid session token
        if not self.settings.token.trust:
            LOGGER.debug("No trust token found")
            return False
        # Verify Cookies are still valid
        for cookie in Meta.get_fields(AccountLoginResponseCookies, "cookie"):
            if cookie not in self.cookies:
                LOGGER.debug(f"Cookie {cookie.key} is missing")
                return False
            # Cookie data is too old
            if self.cookies[cookie].is_expired():
                LOGGER.debug(f"Cookie {cookie.key} is expired")
                return False
        return True

    async def session_reset_config(self):
        """Reset config."""
        LOGGER.debug("Config is in an inconsistent state. Resetting ...")
        self.settings.client_settings.reset_field("scnt")
        self.settings.token.reset_field("session")
        self.settings.token.reset_field("trust")

    @ModelTree.set_context(name="refresh_signin")
    async def session_reset_cookies(self) -> bool:
        """Reset cookies. Set refresh_sigin to True to force a new session."""
        LOGGER.debug("Cookies are in an inconsistent state. Resetting ...")
        self.cookies.pop("aasp", None)
        self.cookies.pop("acn01", None)
        return False

    @ModelTree.with_context
    @ModelTree.set_context(name="response")
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

    @ModelTree.with_context
    async def password_ask(self):
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
    @ModelTree.with_context
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
            await client.send(session.request.model_dump_request())
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

    @ModelTree.with_context
    async def is_security_code_required(self, response: BaseResponse | None = None) -> int:
        """Return False if a trust token is not present or is not valid anymore."""
        if response and Header.TRUST_TOKEN_ELIGIBLE in response.headers:
            LOGGER.debug("2FA is pending")
            return True
        if self.settings.client_settings.trust_eligible and not self.settings.token.trust:
            LOGGER.debug("Missing session token for a 2FA account")
            return True
        return False

    @ModelTree.set_context(name="response")
    @ModelTree.with_context
    async def security_code_reset(self, response: BaseResponse | None = None):
        if response is None or bool(response):
            return
        # If a previous attempt failed, show error...
        error = response.errors.pop(0)
        LOGGER.debug(f"Resetting security code: '{error.message}' ({error.code})")
        self.hooks.on_security_code_error(error)

    @ModelTree.set_context(name="security_code")
    async def security_code_ask(self) -> str:
        # and ask for a new password
        while True:
            code = await asyncio.to_thread(self.hooks.get_security_code)
            code = re.sub(r"[-_\s]", "", code)
            if re.fullmatch(r"\d{6}", code):
                LOGGER.debug(f"Set security_code to: '{code}'")
                return code

    @ModelTree.with_context
    async def security_code(self, security_code: str | None = None) -> BaseResponse:
        """Compomete 2FA verification with a valid code"""
        data = {"security_code": security_code}
        session = SecurityCode(settings=self.settings, cookies=self.cookies, data=data, client=self.client)
        async with session as complete:
            LOGGER.debug(f"Verifing HSA2 code: '{session.request.body.security_code}'")
            await complete.send(session.request.model_dump_request())
        return session.response

    async def trust(self) -> BaseResponse:
        """Trust the session."""
        assert self.settings.token.session, "Session token is required to trust the session."
        session = Trust(settings=self.settings, cookies=self.cookies, client=self.client)
        async with session as complete:
            LOGGER.debug(f"Trust session with: '{self.settings.token.session[:7]}...'")
            await complete.send(session.request.model_dump_request())
        return session.response

    async def account_login(self, require_trust_token=True) -> BaseResponse:
        """Fetch account login."""
        if require_trust_token and not self.settings.token.trust:
            raise ValueError("Trust token is required to fetch account login.")
        session = AccountLogin(settings=self.settings, cookies=self.cookies, client=self.client)
        async with session as complete:
            LOGGER.debug(f"Fetch account details for: '{self.settings.account.username}'")
            await complete.send(session.request.model_dump_request())
        return session.response


class SetupTree(BehaveTree[SetupModelTree]):
    def _on_error(self, err: Exception) -> tuple[TreeAction, Exception | Any | None]:
        if isinstance(err, PyiCloudUserCancelledError):
            return TreeAction.EXIT, str(err)
        return super()._on_error(err)

    def _setup(self) -> bt.AsyncInnerFunction:
        signin_subtree = bt.sequence(
            children=[
                # If response is present and False, there is an error. Show it and
                # reset password and response context
                bt.always_success(self._model.password_reset_if_needed),
                bt.fallback(
                    children=[
                        # Check if password is defined. If not, ask for it
                        bt.inverter(self._model.password_is_needed),
                        self._model.password_ask,
                    ]
                ),
                # Try to login
                bt.fallback(
                    children=[
                        bt.condition(target=self._model.signin),
                        bt.sequence(
                            children=[
                                bt.always_success(self._model.session_reset_config),
                                bt.always_success(self._model.session_reset_cookies),
                            ],
                        ),
                    ]
                ),
            ]
        )

        security_code_subtree = bt.fallback(
            children=[
                # Check response to see if 2FA is needed. A non 0 code is interpreted as False
                bt.inverter(self._model.is_security_code_required),
                bt.sequence(
                    children=[
                        self._model.security_code_are_preconditions_met,
                        # If response is False, there is an error. Show it
                        # and reset response context
                        bt.always_success(self._model.security_code_reset),
                        bt.always_success(self._model.security_code_ask),
                        # If 2FA is needed, verify code
                        self._model.security_code,
                        # Trust session code,
                        self._model.trust,
                    ],
                ),
            ]
        )

        account_login_subtree = bt.sequence(
            children=[
                # Get Account Login,
                bt.action(self._model.account_login, require_trust_token=True),
                # Validate response to ensure we are logged in
                self._model.session_is_valid,
            ]
        )

        return bt.fallback(
            children=[
                self._model.session_is_valid,
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
