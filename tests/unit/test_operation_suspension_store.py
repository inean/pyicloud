from __future__ import annotations

from pyicloud.adapters.operation_suspension import FileSuspendedOperationStore, InMemorySuspendedOperationStore
from pyicloud.domain.api_models import SuspendedOperation


def _operation(*, operation_id: str, now: int, expires_at: int) -> SuspendedOperation:
    return SuspendedOperation(
        operation_id=operation_id,
        account_id="success@example.com",
        method="GET",
        path="/v1/devices",
        query_string="",
        body_text=None,
        content_type=None,
        idempotency_key=None,
        state="pending_auth",
        challenge_id=None,
        created_at=now,
        updated_at=now,
        expires_at=expires_at,
    )


def test_in_memory_suspended_operation_store_marks_expired() -> None:
    now = [1000.0]
    store = InMemorySuspendedOperationStore(clock=lambda: now[0])
    store.save_operation(_operation(operation_id="op-1", now=1000, expires_at=1005))

    pending = store.get_operation("op-1")
    assert pending is not None
    assert pending.state == "pending_auth"

    now[0] = 1006.0
    expired = store.get_operation("op-1")
    assert expired is not None
    assert expired.state == "expired"


def test_file_suspended_operation_store_persists_and_expires(tmp_path) -> None:
    now = [2000.0]
    store = FileSuspendedOperationStore(root_dir=tmp_path, clock=lambda: now[0])
    store.save_operation(_operation(operation_id="op-1", now=2000, expires_at=2010))

    second = FileSuspendedOperationStore(root_dir=tmp_path, clock=lambda: now[0])
    pending = second.get_operation("op-1")
    assert pending is not None
    assert pending.state == "pending_auth"

    now[0] = 2011.0
    expired = second.get_operation("op-1")
    assert expired is not None
    assert expired.state == "expired"
