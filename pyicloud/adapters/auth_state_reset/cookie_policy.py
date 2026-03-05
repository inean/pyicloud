"""Cookie-based auth retry-state reset policy."""

from __future__ import annotations

from pyicloud.constants import AppleCookies as Cookie
from pyicloud.log import LOGGER
from pyicloud.models.cookies import Cookies
from pyicloud.models.settings import Settings
from pyicloud.ports import AuthStateResetPolicy


class CookieAuthStateResetPolicy(AuthStateResetPolicy):
    """Infrastructure policy that keeps locale cookies and purges retry-unsafe auth cookies."""

    SIGNIN_RETRY_COOKIE_WHITELIST: frozenset[str] = frozenset({Cookie.DSLANG, Cookie.SITE})

    def reset_for_signin_retry(self, *, settings: Settings, cookies: Cookies) -> None:  # noqa: ARG002
        kept, removed = cookies.retain_only_keys(self.SIGNIN_RETRY_COOKIE_WHITELIST)
        LOGGER.debug(
            "Reset signin retry cookies: kept=%s removed=%s",
            sorted(kept),
            sorted(removed),
        )
