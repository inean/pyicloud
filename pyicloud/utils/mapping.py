"""Compatibility facade for mapping helpers moved to shared kernel."""

from pyicloud.shared.kernel.mapping import (  # noqa: F401
    compare,
    deep_getitem,
    deep_popitem,
    deep_setitem,
    deep_update,
    flatten,
    map,
    unflatten,
)

__all__ = [
    "compare",
    "deep_getitem",
    "deep_popitem",
    "deep_setitem",
    "deep_update",
    "flatten",
    "map",
    "unflatten",
]
