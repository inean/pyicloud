"""CLI command-group registration helpers."""

from .account import register_account_commands
from .auth import register_auth_commands
from .devices import register_devices_commands
from .drive import register_drive_commands

__all__ = [
    "register_auth_commands",
    "register_devices_commands",
    "register_account_commands",
    "register_drive_commands",
]
