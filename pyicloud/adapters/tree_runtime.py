"""File-backed runtime lifecycle adapter for auth/session trees."""

from __future__ import annotations

from collections.abc import Callable
from functools import partial

from pyicloud.log import PyiCloudPasswordFilter
from pyicloud.models.cookies import Cookies
from pyicloud.models.settings import Settings
from pyicloud.paths import CookiesJar, SettingsFile
from pyicloud.ports import TreeRuntimeLifecyclePort


class FileBackedTreeRuntimeAdapter(TreeRuntimeLifecyclePort):
    """Bridge tree runtime lifecycle events to file-backed settings/cookies state."""

    def attach(self, *, settings: Settings, cookies: Cookies) -> Callable[[], None]:
        password_handler = partial(PyiCloudPasswordFilter.on_changed_password, context=settings)

        def settings_sync_handler(_username: str) -> None:
            SettingsFile(settings).loads()

        def cookies_sync_handler(username: str) -> None:
            CookiesJar(cookies).loads(username=username)

        PyiCloudPasswordFilter.register(settings)
        settings.account.events.password.connect(password_handler)
        settings.account.events.username.connect(settings_sync_handler)
        settings.account.events.username.connect(cookies_sync_handler)

        detached = False

        def detach() -> None:
            nonlocal detached
            if detached:
                return
            detached = True

            settings.account.events.password.disconnect(password_handler)
            settings.account.events.username.disconnect(settings_sync_handler)
            settings.account.events.username.disconnect(cookies_sync_handler)
            PyiCloudPasswordFilter.unregister(settings)

        return detach

    def sync_now(self, *, settings: Settings, cookies: Cookies, username: str) -> None:
        if not username:
            raise ValueError("Username is required")
        SettingsFile(settings).loads()
        CookiesJar(cookies).loads(username=username)


__all__ = ["FileBackedTreeRuntimeAdapter"]
