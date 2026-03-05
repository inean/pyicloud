"""Correlation context helpers for upstream traffic tracing."""

from __future__ import annotations

import hashlib
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any
from uuid import uuid4

_upstream_context: ContextVar[dict[str, str]] = ContextVar("_upstream_context", default={})


def _hash_account(username: str) -> str:
    value = username.strip().lower()
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def current_upstream_context() -> dict[str, str]:
    """Return the current upstream correlation context."""
    return dict(_upstream_context.get())


def current_flow_id() -> str | None:
    """Return the active flow id, if available."""
    value = _upstream_context.get().get("flow_id")
    return str(value) if value else None


def ensure_upstream_context(
    *,
    flow_id: str | None = None,
    operation: str | None = None,
    step: str | None = None,
    username: str | None = None,
    account_hash: str | None = None,
) -> dict[str, str]:
    """Ensure a correlation context exists in the current execution scope."""
    current = dict(_upstream_context.get())

    resolved_flow_id = flow_id or current.get("flow_id") or str(uuid4())
    current["flow_id"] = resolved_flow_id

    if operation:
        current["operation"] = operation.strip().lower()
    else:
        current.setdefault("operation", "unknown")

    if step:
        current["step"] = step.strip().lower()

    if username:
        current["account_hash"] = _hash_account(username)
    elif account_hash:
        current["account_hash"] = account_hash
    else:
        current.setdefault("account_hash", "anonymous")

    _upstream_context.set(current)
    return dict(current)


@contextmanager
def bind_upstream_context(
    *,
    flow_id: str | None = None,
    operation: str | None = None,
    step: str | None = None,
    username: str | None = None,
    account_hash: str | None = None,
):
    """Temporarily bind correlation attributes for upstream probe events."""
    parent = dict(_upstream_context.get())
    next_ctx = dict(parent)

    next_ctx["flow_id"] = flow_id or parent.get("flow_id") or str(uuid4())
    if operation:
        next_ctx["operation"] = operation.strip().lower()
    if step:
        next_ctx["step"] = step.strip().lower()
    if username:
        next_ctx["account_hash"] = _hash_account(username)
    elif account_hash:
        next_ctx["account_hash"] = account_hash

    next_ctx.setdefault("operation", "unknown")
    next_ctx.setdefault("account_hash", "anonymous")

    token = _upstream_context.set(next_ctx)
    try:
        yield dict(next_ctx)
    finally:
        _upstream_context.reset(token)


def inject_flow_into_payload(payload: dict[str, Any], *, flow_id: str) -> dict[str, Any]:
    """Persist flow id in session payload metadata for later correlation reuse."""
    cloned = dict(payload)
    cloned["__flow_id"] = flow_id
    return cloned
