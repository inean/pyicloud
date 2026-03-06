"""Compatibility shim for auth/session ports moved to semantic contexts."""

from pyicloud.contexts.crosscutting.auth.contracts.auth import (
    AuthSessionPort,
    ServiceEndpointPort,
    SessionStorePort,
)

__all__ = ["AuthSessionPort", "ServiceEndpointPort", "SessionStorePort"]
