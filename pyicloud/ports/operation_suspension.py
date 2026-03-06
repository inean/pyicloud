"""Compatibility shim for operation suspension ports moved to semantic contexts."""

from pyicloud.contexts.crosscutting.auth.contracts.operation_suspension import (
    SuspendedOperationCommandPort,
    SuspendedOperationQueryPort,
)

__all__ = ["SuspendedOperationCommandPort", "SuspendedOperationQueryPort"]
