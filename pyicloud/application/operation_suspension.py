"""Compatibility shim for operation suspension service moved to auth context."""

from pyicloud.contexts.crosscutting.auth.application.operation_suspension import OperationSuspensionService

__all__ = ["OperationSuspensionService"]
