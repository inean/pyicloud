from __future__ import annotations

import pytest

from pyicloud.adapters.operation_suspension import InMemorySuspendedOperationStore
from pyicloud.contexts.crosscutting.auth.application.operation_suspension import OperationSuspensionService
from pyicloud.domain import Conflict


def _service() -> OperationSuspensionService:
    store = InMemorySuspendedOperationStore()
    return OperationSuspensionService(query=store, command=store, ttl_seconds=300)


def test_suspend_and_attach_challenge() -> None:
    service = _service()
    operation = service.suspend_operation(
        account_id="success@example.com",
        method="GET",
        path="/v1/devices",
        query_string="",
        body_text=None,
        content_type=None,
        idempotency_key=None,
    )
    assert operation.state == "pending_auth"

    attached = service.attach_challenge(
        operation_id=operation.operation_id,
        challenge_id="challenge-1",
    )
    assert attached.challenge_id == "challenge-1"


def test_mark_resuming_completed_and_failed_transitions() -> None:
    service = _service()
    operation = service.suspend_operation(
        account_id="success@example.com",
        method="POST",
        path="/v1/reminders",
        query_string="",
        body_text='{"title":"x"}',
        content_type="application/json",
        idempotency_key="idem-1",
    )

    resuming = service.mark_resuming(operation_id=operation.operation_id)
    assert resuming.state == "resuming"

    completed = service.mark_completed(
        operation_id=operation.operation_id,
        response_status=200,
        response_payload={"data": {"ok": True}},
    )
    assert completed.state == "completed"
    assert completed.response_status == 200

    with pytest.raises(Conflict, match="completed"):
        service.mark_failed(operation_id=operation.operation_id, error="boom")


def test_mark_resuming_rejects_terminal_states() -> None:
    service = _service()
    operation = service.suspend_operation(
        account_id="success@example.com",
        method="GET",
        path="/v1/devices",
        query_string="",
        body_text=None,
        content_type=None,
        idempotency_key=None,
    )
    service.mark_failed(operation_id=operation.operation_id, error="failure")

    with pytest.raises(Conflict, match="terminal"):
        service.mark_resuming(operation_id=operation.operation_id)


def test_suspend_operation_enforces_payload_size_limit() -> None:
    store = InMemorySuspendedOperationStore()
    service = OperationSuspensionService(
        query=store,
        command=store,
        ttl_seconds=300,
        max_payload_bytes=8,
    )

    with pytest.raises(Conflict, match="size limit"):
        service.suspend_operation(
            account_id="success@example.com",
            method="POST",
            path="/v1/reminders",
            query_string="",
            body_text="this payload is too long",
            content_type="text/plain",
            idempotency_key="idem-1",
        )


def test_suspend_operation_enforces_per_user_and_global_quotas() -> None:
    store = InMemorySuspendedOperationStore()
    service = OperationSuspensionService(
        query=store,
        command=store,
        ttl_seconds=300,
        max_pending_per_user=1,
        max_pending_global=2,
    )
    service.suspend_operation(
        account_id="a@example.com",
        method="GET",
        path="/v1/devices",
        query_string="",
        body_text=None,
        content_type=None,
        idempotency_key=None,
    )
    with pytest.raises(Conflict, match="Per-user"):
        service.suspend_operation(
            account_id="a@example.com",
            method="GET",
            path="/v1/account/storage",
            query_string="",
            body_text=None,
            content_type=None,
            idempotency_key=None,
        )

    service.suspend_operation(
        account_id="b@example.com",
        method="GET",
        path="/v1/devices",
        query_string="",
        body_text=None,
        content_type=None,
        idempotency_key=None,
    )
    with pytest.raises(Conflict, match="Global"):
        service.suspend_operation(
            account_id="c@example.com",
            method="GET",
            path="/v1/devices",
            query_string="",
            body_text=None,
            content_type=None,
            idempotency_key=None,
        )
