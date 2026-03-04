"""Compatibility service facade for legacy `PyiCloudService` imports."""

from __future__ import annotations

import asyncio
import warnings
from typing import Any

from pyicloud.adapters.auth import authenticate_legacy_endpoint
from pyicloud.services import PyiCloudServices


class PyiCloudService:
    """Compatibility facade that composes existing auth and service adapters."""

    def __init__(self, username: str, password: str = "", *, interactive: bool | None = None):
        warnings.warn(
            "PyiCloudService compatibility facade is deprecated; migrate to pyicloud API/CLI services.",
            DeprecationWarning,
            stacklevel=2,
        )
        if interactive is None:
            interactive = password == ""

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            # No running loop in this thread.
            pass
        else:
            raise RuntimeError(
                "PyiCloudService cannot be instantiated inside a running event loop. "
                "Use API/CLI services from asynchronous contexts."
            )

        endpoint = asyncio.run(
            authenticate_legacy_endpoint(
                username=username,
                password=password,
                interactive=interactive,
            )
        )
        self._services = PyiCloudServices(endpoint=endpoint)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._services, name)

    def __repr__(self) -> str:
        return repr(self._services)
