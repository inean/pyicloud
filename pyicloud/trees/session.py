"""Library base file."""

from __future__ import annotations

from collections.abc import Sequence
from contextvars import copy_context
from typing import Any, Coroutine, cast, override

from pyicloud.log import LOGGER
from pyicloud.models import Meta
from pyicloud.sessions import BaseResponse
from pyicloud.sessions.session import SessionCookies
from pyicloud.sessions.validate import Validate
from pyicloud.trees import BehaveTree, Tree, TreeState, TreeTransitionExtra, blackboard


class SessionModelTree(Tree):
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
        for cookie in Meta.get_fields(SessionCookies, "cookie"):
            if cookie not in self.cookies:
                LOGGER.debug(f"Cookie {cookie.key} is missing")
                return True
            # Cookie data is too old
            if self.cookies[cookie].is_expired():
                LOGGER.debug(f"Cookie {cookie.key} is expired")
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
        """Reset cookies. Set refresh_sigin to True to force a new session."""
        LOGGER.debug("Cookies are in an inconsistent state. Resetting ...")
        self.cookies.pop("aasp", None)
        self.cookies.pop("acn01", None)
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
