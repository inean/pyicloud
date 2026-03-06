"""CLI command-group registration helpers."""

from .account import register_account_commands
from .auth import register_auth_commands
from .calendar import register_calendar_commands
from .contacts import register_contacts_commands
from .devices import register_devices_commands
from .drive import register_drive_commands
from .observability import register_observability_commands
from .photos import register_photos_commands
from .reminders import register_reminders_commands
from .ubiquity import register_ubiquity_commands

__all__ = [
    "register_auth_commands",
    "register_devices_commands",
    "register_account_commands",
    "register_calendar_commands",
    "register_contacts_commands",
    "register_drive_commands",
    "register_observability_commands",
    "register_photos_commands",
    "register_reminders_commands",
    "register_ubiquity_commands",
]
