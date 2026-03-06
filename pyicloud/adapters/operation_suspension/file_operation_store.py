"""File-backed suspended-operation store with TTL-aware expiry handling."""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Mapping
from dataclasses import replace
from pathlib import Path
from time import time
from typing import Any, cast

from pyicloud.domain.api_models import SuspendedOperation, SuspendedOperationState
from pyicloud.ports import SuspendedOperationCommandPort, SuspendedOperationQueryPort

_TERMINAL_STATES = {"completed", "failed", "expired"}
_VALID_STATES = {"pending_auth", "resuming", "completed", "failed", "expired"}


def _normalize_operation(record: Mapping[str, Any]) -> SuspendedOperation:
    operation_id = str(record.get("operation_id", "")).strip()
    account_id = str(record.get("account_id", "")).strip()
    method = str(record.get("method", "")).strip().upper()
    path = str(record.get("path", "")).strip()
    query_string = str(record.get("query_string", "")).strip()
    state = str(record.get("state", "")).strip()
    if not operation_id or not account_id or not method or not path:
        raise RuntimeError("Invalid suspended operation record identity")
    if state not in _VALID_STATES:
        raise RuntimeError(f"Invalid suspended operation state: {state}")
    typed_state = cast(SuspendedOperationState, state)
    try:
        created_at = int(record.get("created_at", 0))
        updated_at = int(record.get("updated_at", 0))
        expires_at = int(record.get("expires_at", 0))
    except (TypeError, ValueError) as err:
        raise RuntimeError("Invalid suspended operation timestamps") from err
    raw_status = record.get("response_status")
    if raw_status is None:
        response_status: int | None = None
    else:
        try:
            response_status = int(raw_status)
        except (TypeError, ValueError) as err:
            raise RuntimeError("Invalid suspended operation response_status") from err
    response_payload = record.get("response_payload")
    if response_payload is not None and not isinstance(response_payload, dict):
        raise RuntimeError("Invalid suspended operation response_payload")
    return SuspendedOperation(
        operation_id=operation_id,
        account_id=account_id,
        method=method,
        path=path,
        query_string=query_string,
        body_text=str(record.get("body_text", "")) if record.get("body_text") is not None else None,
        content_type=str(record.get("content_type", "")) if record.get("content_type") is not None else None,
        idempotency_key=str(record.get("idempotency_key", "")) if record.get("idempotency_key") is not None else None,
        state=typed_state,
        challenge_id=str(record.get("challenge_id", "")) if record.get("challenge_id") is not None else None,
        created_at=created_at,
        updated_at=updated_at,
        expires_at=expires_at,
        response_status=response_status,
        response_payload=dict(response_payload) if isinstance(response_payload, dict) else None,
        error=str(record.get("error", "")) if record.get("error") is not None else None,
    )


def _record_from_operation(operation: SuspendedOperation) -> dict[str, Any]:
    return {
        "operation_id": operation.operation_id,
        "account_id": operation.account_id,
        "method": operation.method,
        "path": operation.path,
        "query_string": operation.query_string,
        "body_text": operation.body_text,
        "content_type": operation.content_type,
        "idempotency_key": operation.idempotency_key,
        "state": operation.state,
        "challenge_id": operation.challenge_id,
        "created_at": operation.created_at,
        "updated_at": operation.updated_at,
        "expires_at": operation.expires_at,
        "response_status": operation.response_status,
        "response_payload": operation.response_payload,
        "error": operation.error,
    }


class FileSuspendedOperationStore(SuspendedOperationQueryPort, SuspendedOperationCommandPort):
    """Persist suspended operation records as JSON for multi-process durability."""

    def __init__(
        self,
        *,
        root_dir: str | os.PathLike[str] | None = None,
        clock: Callable[[], float] | None = None,
    ):
        if root_dir is None:
            root_dir = os.getenv("PYICLOUD_API_OPERATION_STORE_DIR", ".cache/pyicloud/suspended-operations")
        self._root = Path(root_dir).expanduser()
        self._root.mkdir(parents=True, exist_ok=True)
        self._path = self._root / "operations.json"
        self._clock = clock or time

    @staticmethod
    def _empty_state() -> dict[str, dict[str, Any]]:
        return {"operations": {}}

    def _read_state(self) -> dict[str, dict[str, Any]]:
        if not self._path.exists():
            return self._empty_state()
        try:
            payload = json.loads(self._path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as err:
            raise RuntimeError(f"Invalid suspended operation payload: {self._path}") from err
        if not isinstance(payload, dict):
            raise RuntimeError(f"Invalid suspended operation payload shape: {self._path}")
        operations = payload.get("operations")
        if not isinstance(operations, dict):
            raise RuntimeError(f"Invalid suspended operation payload shape: {self._path}")
        return {"operations": dict(operations)}

    def _write_state(self, state: Mapping[str, Mapping[str, Any]]) -> None:
        self._root.mkdir(parents=True, exist_ok=True)
        tmp_path = self._path.with_suffix(".tmp")
        tmp_path.write_text(
            json.dumps(state, separators=(",", ":")),
            encoding="utf-8",
        )
        tmp_path.replace(self._path)

    def _load_operations(self) -> dict[str, SuspendedOperation]:
        state = self._read_state()
        loaded: dict[str, SuspendedOperation] = {}
        for operation_id, raw in state["operations"].items():
            if not isinstance(raw, dict):
                raise RuntimeError("Invalid suspended operation entry")
            operation = _normalize_operation(raw)
            if operation.operation_id != operation_id:
                raise RuntimeError("Suspended operation ID mismatch")
            loaded[operation_id] = operation
        return loaded

    def _store_operations(self, operations: Mapping[str, SuspendedOperation]) -> None:
        payload = {"operations": {operation_id: _record_from_operation(op) for operation_id, op in operations.items()}}
        self._write_state(payload)

    def _expire_operations(self, operations: dict[str, SuspendedOperation]) -> bool:
        changed = False
        now = int(self._clock())
        for operation_id, operation in list(operations.items()):
            if operation.state in _TERMINAL_STATES:
                continue
            if operation.expires_at <= now:
                operations[operation_id] = replace(
                    operation,
                    state="expired",
                    updated_at=now,
                    error=operation.error or "Operation expired",
                )
                changed = True
        return changed

    def get_operation(self, operation_id: str) -> SuspendedOperation | None:
        operations = self._load_operations()
        if self._expire_operations(operations):
            self._store_operations(operations)
        return operations.get(operation_id)

    def save_operation(self, operation: SuspendedOperation) -> None:
        operations = self._load_operations()
        self._expire_operations(operations)
        operations[operation.operation_id] = operation
        self._store_operations(operations)

    def delete_operation(self, operation_id: str) -> None:
        operations = self._load_operations()
        self._expire_operations(operations)
        operations.pop(operation_id, None)
        self._store_operations(operations)
