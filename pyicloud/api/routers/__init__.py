"""API domain routers."""

from .account import router as account_router
from .auth import router as auth_router
from .calendar import router as calendar_router
from .contacts import router as contacts_router
from .devices import router as devices_router
from .drive import router as drive_router
from .observability import router as observability_router
from .photos import router as photos_router
from .reminders import router as reminders_router
from .ubiquity import router as ubiquity_router

__all__ = [
    "auth_router",
    "devices_router",
    "account_router",
    "calendar_router",
    "contacts_router",
    "drive_router",
    "observability_router",
    "photos_router",
    "reminders_router",
    "ubiquity_router",
]
