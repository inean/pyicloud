"""Application service for suspended-operation lifecycle and state transitions."""

from __future__ import annotations

from dataclasses import replace
from time import time
from uuid import uuid4

from pyicloud.domain import Conflict, SuspendedOperation
from pyicloud.ports import SuspendedOperationCommandPort, SuspendedOperationQueryPort

_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_TERMINAL_STATES = {"completed", "failed", "expired"}


class OperationSuspensionService:
    """Manage operation suspension records used by challenge-driven auth resume flows."""

    def __init__(
        self,
        *,
        query: SuspendedOperationQueryPort,
        command: SuspendedOperationCommandPort,
        ttl_seconds: int = 300,
    ):
        self._query = query
        self._command = command
        self._ttl_seconds = max(30, int(ttl_seconds))

    @property
    def query_port(self) -> SuspendedOperationQueryPort:
        """Expose query port for advanced orchestration hooks."""
        return self._query

    @property
    def command_port(self) -> SuspendedOperationCommandPort:
        """Expose command port for migrations and maintenance flows."""
        return self._command

    @staticmethod
    def is_mutating_method(method: str) -> bool:
        return str(method).strip().upper() in _MUTATING_METHODS

    def suspend_operation(
        self,
        *,
        account_id: str,
        method: str,
        path: str,
        query_string: str,
        body_text: str | None,
        content_type: str | None,
        idempotency_key: str | None,
    ) -> SuspendedOperation:
        now = int(time())
        operation = SuspendedOperation(
            operation_id=str(uuid4()),
            account_id=str(account_id).strip(),
            method=str(method).strip().upper(),
            path=str(path).strip(),
            query_string=str(query_string or ""),
            body_text=body_text,
            content_type=content_type,
            idempotency_key=idempotency_key,
            state="pending_auth",
            challenge_id=None,
            created_at=now,
            updated_at=now,
            expires_at=now + self._ttl_seconds,
        )
        self._command.save_operation(operation)
        return operation

    def attach_challenge(self, *, operation_id: str, challenge_id: str) -> SuspendedOperation:
        operation = self.get_operation(operation_id=operation_id)
        if operation is None:
            raise Conflict("Suspended operation is missing")
        if operation.state in _TERMINAL_STATES:
            raise Conflict(f"Cannot attach challenge to terminal operation state: {operation.state}")
        updated = replace(
            operation,
            challenge_id=str(challenge_id).strip() or operation.challenge_id,
            updated_at=int(time()),
        )
        self._command.save_operation(updated)
        return updated

    def get_operation(self, *, operation_id: str) -> SuspendedOperation | None:
        return self._query.get_operation(str(operation_id).strip())

    def mark_resuming(self, *, operation_id: str) -> SuspendedOperation:
        operation = self.get_operation(operation_id=operation_id)
        if operation is None:
            raise Conflict("Suspended operation is missing")
        if operation.state == "resuming":
            return operation
        if operation.state in _TERMINAL_STATES:
            raise Conflict(f"Suspended operation is already terminal: {operation.state}")
        updated = replace(operation, state="resuming", updated_at=int(time()))
        self._command.save_operation(updated)
        return updated

    def mark_completed(
        self,
        *,
        operation_id: str,
        response_status: int,
        response_payload: dict[str, object] | None,
    ) -> SuspendedOperation:
        operation = self.get_operation(operation_id=operation_id)
        if operation is None:
            raise Conflict("Suspended operation is missing")
        if operation.state == "completed":
            return operation
        if operation.state in {"failed", "expired"}:
            raise Conflict(f"Cannot complete suspended operation from terminal state: {operation.state}")
        updated = replace(
            operation,
            state="completed",
            updated_at=int(time()),
            response_status=int(response_status),
            response_payload=response_payload,
            error=None,
        )
        self._command.save_operation(updated)
        return updated

    def mark_failed(self, *, operation_id: str, error: str) -> SuspendedOperation:
        operation = self.get_operation(operation_id=operation_id)
        if operation is None:
            raise Conflict("Suspended operation is missing")
        if operation.state == "failed":
            return operation
        if operation.state == "completed":
            raise Conflict("Cannot fail a completed suspended operation")
        updated = replace(
            operation,
            state="failed",
            updated_at=int(time()),
            error=str(error).strip() or "Operation resume failed",
        )
        self._command.save_operation(updated)
        return updated
