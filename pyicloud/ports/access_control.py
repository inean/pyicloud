"""Compatibility shim for access-control ports moved to semantic contexts."""

from pyicloud.contexts.crosscutting.auth.contracts.access_control import (
    AccessControlCommandPort,
    AccessControlQueryPort,
)

__all__ = ["AccessControlCommandPort", "AccessControlQueryPort"]
