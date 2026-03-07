"""Library base file."""

from __future__ import annotations

from collections.abc import Coroutine, Sequence
from contextvars import copy_context
from typing import Any, cast, override

from pyicloud.log import LOGGER
from pyicloud.models.fields import MorselModel
from pyicloud.platform.legacy_auth_tree.engine import BehaveTree, Tree, TreeState, TreeTransitionExtra, blackboard
from pyicloud.ports import AuthStateResetPolicy
from pyicloud.sessions._contracts import BaseResponse
from pyicloud.sessions.validate import Validate, ValidateRequestCookies


class _NoopAuthStateResetPolicy(AuthStateResetPolicy):
    def reset_for_signin_retry(self, *, settings, cookies) -> None:  # noqa: ANN001, ARG002
        return None


class SessionModelTree(Tree):
    auth_reset_policy: AuthStateResetPolicy

    def __init__(
        self,
        *,
        auth_reset_policy: AuthStateResetPolicy | None = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.auth_reset_policy = auth_reset_policy or _NoopAuthStateResetPolicy()

    @blackboard(fetch=True, remove="refresh_signin")
    def _session_is_valid(self, refresh_signin=False) -> bool:
        """Test that we have required session data to operate services without the need to re-authenticate."""
        # Check if we have a valid username
        if not self._session_is_logged():
            LOGGER.debug("No previous account info found")
            return False
        # Check if we have a valid session token
        if not self.settings.token.trust:
            LOGGER.debug("No trust token found")
            return False
        # Verify Cookies are still valid
        if self._session_is_expired():
            return False
        # Check if a refresh is forced
        if refresh_signin:
            LOGGER.debug("Refreshing session")
            return False
        return True

    def _session_is_logged(self) -> bool:
        """Test that we have required session data to operate services."""
        # Check if we have a valid username
        if not self.settings.account.username:
            LOGGER.debug("No account info found")
            return False
        # Check if we have a valid session token
        if not self.settings.token.session:
            LOGGER.debug("No session token found")
            return False
        return True

    def _session_is_expired(self):
        for _, cookie_name, field_info in ValidateRequestCookies.model_fields_from_meta(by_meta="cookie"):
            if not field_info.is_required():
                continue
            if cookie_name not in self.cookies:
                LOGGER.debug(f"Cookie {cookie_name} is missing")
                return True
            # Cookie data is too old
            cookie = self.cookies[cookie_name]
            assert isinstance(cookie, MorselModel), f"Invalid cookie type: {type(cookie)}"
            if cookie.is_expired():
                LOGGER.debug(f"Cookie {cookie_name} is expired")
                return True
        # Cookies are still valid
        return False

    def _session_reset_config(self):
        """Reset config."""
        LOGGER.debug("Config is in an inconsistent state. Resetting ...")
        self.settings.client_settings.reset_field("scnt")
        self.settings.token.reset_field("session")
        self.settings.token.reset_field("trust")

    @blackboard(store="refresh_signin")
    def _session_reset_cookies(self) -> bool:
        """Reset auth artifacts for signin retry through the configured reset policy."""
        LOGGER.debug("Auth retry state is inconsistent. Applying reset policy ...")
        self.auth_reset_policy.reset_for_signin_retry(settings=self.settings, cookies=self.cookies)
        return False

    @blackboard(store=("api", lambda x: cast(BaseResponse, x).body, lambda x: bool(x)))
    async def session_validate(self):
        session = Validate(settings=self.settings, cookies=self.cookies, client=self.client)
        async with session as complete:
            LOGGER.debug("Renewing session using cookies")
            await complete.send(session.request.create_request())
        return session.response

    @property
    def transitions(self) -> Sequence[TreeTransitionExtra]:
        return [
            {
                "trigger": "session_validate",
                "source": TreeState.SESSION_LOGGED,
                "dest": TreeState.SESSION_ACTIVE,
                "error": TreeState.SESSION_CLOSED,
                "action": self.session_validate,
                "result": "api",
            },
        ]

    @override
    def run(self, bhtree: BehaveTree, *args, **kwargs) -> tuple[Any]:
        with self.context(**kwargs):
            coro = self.bhtree()
            resp = bhtree.runner.run(cast(Coroutine[Any, Any, Any], coro), context=copy_context())
            return resp
