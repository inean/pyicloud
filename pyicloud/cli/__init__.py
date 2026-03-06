"""Compatibility package forwarding imports to pyicloud.interfaces.cli."""

from __future__ import annotations

import importlib
import sys

_CANONICAL_ROOT = "pyicloud.interfaces.cli"
_canonical_cli = importlib.import_module(_CANONICAL_ROOT)

sys.modules[__name__] = _canonical_cli

_SUBMODULES = (
    "main",
    "transport",
    "token_store",
    "credential_vault",
    "commands",
    "commands.account",
    "commands.auth",
    "commands.calendar",
    "commands.contacts",
    "commands.devices",
    "commands.drive",
    "commands.observability",
    "commands.photos",
    "commands.reminders",
    "commands.ubiquity",
)

for suffix in _SUBMODULES:
    sys.modules[f"{__name__}.{suffix}"] = importlib.import_module(f"{_CANONICAL_ROOT}.{suffix}")
