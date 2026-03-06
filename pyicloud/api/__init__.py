"""Compatibility package forwarding imports to pyicloud.interfaces.api."""

from __future__ import annotations

import importlib
import sys

_CANONICAL_ROOT = "pyicloud.interfaces.api"
_canonical_api = importlib.import_module(_CANONICAL_ROOT)

sys.modules[__name__] = _canonical_api

_SUBMODULES = (
    "app",
    "dependencies",
    "errors",
    "instrumentation",
    "main",
    "responses",
    "routers",
    "routers.account",
    "routers.admin",
    "routers.auth",
    "routers.calendar",
    "routers.contacts",
    "routers.devices",
    "routers.drive",
    "routers.observability",
    "routers.photos",
    "routers.reminders",
    "routers.ubiquity",
    "schemas",
    "schemas.account",
    "schemas.admin",
    "schemas.auth",
    "schemas.common",
    "schemas.devices",
    "schemas.drive",
    "schemas.library",
    "schemas.observability",
    "schemas.reminders",
)

for suffix in _SUBMODULES:
    sys.modules[f"{__name__}.{suffix}"] = importlib.import_module(f"{_CANONICAL_ROOT}.{suffix}")
