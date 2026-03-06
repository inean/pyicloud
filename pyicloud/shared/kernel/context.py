from __future__ import annotations

from contextlib import asynccontextmanager, contextmanager
from contextvars import ContextVar
from typing import Any

_init_context_var = ContextVar[dict[str, Any]]("_init_context_var", default={})


def update_context_var(value: dict[str, Any]):
    current_value = _init_context_var.get().copy()  # get a copy of the current value
    current_value.update(value)  # update with new values
    return _init_context_var.set(current_value)  # set the updated value


def reset_context_var(token):
    return _init_context_var.reset(token)


@contextmanager
def sync_context(**value: dict[str, Any]):
    token = update_context_var(value)
    try:
        yield
    finally:
        reset_context_var(token)


@asynccontextmanager
async def async_context(**value: dict[str, Any]):
    token = update_context_var(value)
    try:
        yield
    finally:
        reset_context_var(token)


__all__ = [
    "_init_context_var",
    "async_context",
    "reset_context_var",
    "sync_context",
    "update_context_var",
]
