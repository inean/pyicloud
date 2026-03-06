"""Ports for suspended operation persistence used by auth challenge resume flows."""

from __future__ import annotations

from typing import Protocol

from pyicloud.domain.api_models import SuspendedOperation


class SuspendedOperationQueryPort(Protocol):
    """
    Direction: outbound

    Purpose:
        This port isolates read-only retrieval of suspended backend operations
        from API orchestration services that coordinate auth-driven resumes.

        Implementations expose operation state with TTL-aware semantics while
        the application core remains independent from storage details.

    Implemented by: InMemorySuspendedOperationStore, FileSuspendedOperationStore
    """

    def get_operation(self, operation_id: str) -> SuspendedOperation | None:
        """
        OperationSuspensionService and API handlers call this method to load suspended operation context.

        The adapter translates operation identifiers into persisted records and applies expiration handling
        so orchestration code can reason about pending/resuming/completed states consistently.

        Raises:
            RuntimeError: Suspended operation state cannot be read safely from persistence.
        """

    def list_operations(self) -> tuple[SuspendedOperation, ...]:
        """
        OperationSuspensionService calls this method to evaluate quotas and inspect pending operation volume.

        The adapter translates backend-specific iteration into stable SuspendedOperation records so
        abuse-protection policies can apply per-user and global limits consistently.

        Raises:
            RuntimeError: Suspended operation state cannot be enumerated reliably.
        """


class SuspendedOperationCommandPort(Protocol):
    """
    Direction: outbound

    Purpose:
        This port isolates mutation of suspended operation records and state
        transitions from API orchestration services.

        Implementations persist operation lifecycle updates and terminal results,
        allowing resume workflows to remain storage-agnostic.

    Implemented by: InMemorySuspendedOperationStore, FileSuspendedOperationStore
    """

    def save_operation(self, operation: SuspendedOperation) -> None:
        """
        OperationSuspensionService calls this method to persist operation lifecycle transitions.

        The adapter translates domain operation records into backend-specific payloads and guarantees
        updates are durable enough for subsequent challenge and resume attempts.

        Raises:
            RuntimeError: Operation state cannot be persisted reliably.
        """

    def delete_operation(self, operation_id: str) -> None:
        """
        OperationSuspensionService calls this method to remove expired or discarded operation records.

        The adapter translates lifecycle cleanup intent into backend-specific delete behavior while
        keeping storage management concerns outside the application core.

        Raises:
            RuntimeError: Operation state cannot be deleted safely.
        """
