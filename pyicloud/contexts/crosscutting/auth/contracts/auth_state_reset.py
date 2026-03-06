"""Port for auth retry state reset policies."""

from __future__ import annotations

from typing import Protocol

from pyicloud.models.cookies import Cookies
from pyicloud.models.settings import Settings


class AuthStateResetPolicy(Protocol):
    """
    Direction: outbound

    Purpose:
        This port isolates retry-state reset concerns from auth tree orchestration
        so tree nodes do not depend on transport cookie details.

        Implementations decide which auth artifacts are retained or purged for a
        clean signin retry while keeping domain flow logic transport-agnostic.

    Implemented by: CookieAuthStateResetPolicy
    """

    def reset_for_signin_retry(self, *, settings: Settings, cookies: Cookies) -> None:
        """
        SetupModelTree calls this method after a failed signin attempt to prepare retry state.

        The adapter translates retry-reset intent into transport-level cookie cleanup
        while preserving domain-level flow semantics in the tree.

        Raises:
            RuntimeError: Retry state cannot be reset safely.
        """
