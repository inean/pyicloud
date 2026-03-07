"""Canonical legacy tree-auth implementation package."""

from pyicloud.platform.legacy_auth_tree.engine import *  # noqa: F401,F403
from pyicloud.platform.legacy_auth_tree.session import SessionModelTree
from pyicloud.platform.legacy_auth_tree.setup import SetupHooks, SetupModelTree

__all__ = [
    *[name for name in globals() if not name.startswith("_")],
    "SessionModelTree",
    "SetupHooks",
    "SetupModelTree",
]
