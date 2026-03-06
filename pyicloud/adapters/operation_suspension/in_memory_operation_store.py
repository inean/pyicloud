"""In-memory suspended-operation store with TTL-aware expiry handling."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from time import time

from pyicloud.domain.api_models import SuspendedOperation
from pyicloud.ports import SuspendedOperationCommandPort, SuspendedOperationQueryPort

_TERMINAL_STATES = {"completed", "failed", "expired"}


class InMemorySuspendedOperationStore(SuspendedOperationQueryPort, SuspendedOperationCommandPort):
    """Store suspended operations in process memory."""

    def __init__(self, *, clock: Callable[[], float] | None = None):
        self._clock = clock or time
        self._operations: dict[str, SuspendedOperation] = {}

    def _cleanup(self) -> None:
        now = int(self._clock())
        for operation_id, operation in list(self._operations.items()):
            if operation.state in _TERMINAL_STATES:
                continue
            if operation.expires_at <= now:
                self._operations[operation_id] = replace(
                    operation,
                    state="expired",
                    updated_at=now,
                    error=operation.error or "Operation expired",
                )

    def get_operation(self, operation_id: str) -> SuspendedOperation | None:
        self._cleanup()
        return self._operations.get(operation_id)

    def list_operations(self) -> tuple[SuspendedOperation, ...]:
        self._cleanup()
        ordered = sorted(self._operations.values(), key=lambda operation: operation.created_at)
        return tuple(ordered)

    def save_operation(self, operation: SuspendedOperation) -> None:
        self._cleanup()
        self._operations[operation.operation_id] = operation

    def delete_operation(self, operation_id: str) -> None:
        self._cleanup()
        self._operations.pop(operation_id, None)
