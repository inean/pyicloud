"""API domain routers."""

from .account import router as account_router
from .auth import router as auth_router
from .devices import router as devices_router
from .drive import router as drive_router

__all__ = ["auth_router", "devices_router", "account_router", "drive_router"]
