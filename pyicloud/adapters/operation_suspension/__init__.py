"""Adapters for suspended operation persistence."""

from .file_operation_store import FileSuspendedOperationStore
from .in_memory_operation_store import InMemorySuspendedOperationStore

__all__ = ["FileSuspendedOperationStore", "InMemorySuspendedOperationStore"]
