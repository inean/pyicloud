"""Port for tree runtime lifecycle side effects."""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from pyicloud.models.cookies import Cookies
from pyicloud.models.settings import Settings


class TreeRuntimeLifecyclePort(Protocol):
    """
    Direction: outbound

    Purpose:
        This port isolates runtime side effects needed by tree orchestrators so
        tree constructors stay pure and easy to test.

        Implementations translate runtime lifecycle events into infrastructure
        concerns like settings/cookies hydration and log filtering hooks.

    Implemented by: FileBackedTreeRuntimeAdapter
    """

    def attach(self, *, settings: Settings, cookies: Cookies) -> Callable[[], None]:
        """
        Tree orchestrators call this method to subscribe runtime listeners.

        The adapter binds domain model events to infrastructure handlers and
        returns a detach callback that undoes all registered side effects.

        Raises:
            RuntimeError: Runtime listeners cannot be registered safely.
        """

    def sync_now(self, *, settings: Settings, cookies: Cookies, username: str) -> None:
        """
        Tree orchestrators call this method to hydrate runtime state immediately.

        The adapter maps domain settings/cookies into infrastructure-backed
        sources so later auth/session steps operate on synchronized artifacts.

        Raises:
            ValueError: Username is missing or invalid for synchronization.
            RuntimeError: Runtime synchronization cannot be completed safely.
        """


__all__ = ["TreeRuntimeLifecyclePort"]
