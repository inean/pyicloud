"""Shared kernel for stable cross-context contracts."""

from .context import _init_context_var, async_context, reset_context_var, sync_context, update_context_var
from .decorators import Deprecated, classproperty, deprecated
from .mapping import compare, deep_getitem, deep_popitem, deep_setitem, deep_update, flatten, map, unflatten

__all__ = [
    "Deprecated",
    "_init_context_var",
    "async_context",
    "classproperty",
    "compare",
    "deep_getitem",
    "deep_popitem",
    "deep_setitem",
    "deep_update",
    "deprecated",
    "flatten",
    "map",
    "reset_context_var",
    "sync_context",
    "unflatten",
    "update_context_var",
]
