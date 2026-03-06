"""Dictionary related operations"""

from __future__ import annotations

from collections.abc import Callable, Mapping, MutableMapping
from typing import Any


def flatten(d: Mapping, parent_key: str = "", sep: str = ".") -> dict[str, Any]:
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, Mapping):
            items.extend(flatten(v, new_key, sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def unflatten(key: str, value: Any, sep: str = ".") -> dict[str, Any]:
    if sep not in key:
        return {key: value}
    key, child_key = key.split(sep, 1)
    return {key: unflatten(child_key, value, sep)}


def deep_getitem(d: Mapping, key: str, sep="."):
    if sep in key:
        key, child_key = key.split(sep, 1)
        if key not in d:
            raise KeyError(f"{key}")
        return deep_getitem(d[key], child_key, sep)

    if key not in d:
        raise KeyError(f"{key}")
    return d[key]


def deep_setitem(d: MutableMapping, key: str, value: Any, sep="."):
    if sep in key:
        key, child_key = key.split(sep, 1)
        if key not in d:
            raise KeyError(f"{key}")
        if not isinstance(d[key], Mapping):
            raise ValueError(f"Expected {key}. got {type(d[key])}")
        return deep_setitem(d[key], child_key, value, sep)

    old_value = d.get(key, type(value)())
    # Be flexible with the type of the value. Allow None or falsy values
    if old_value and value and not isinstance(value, type(old_value)):
        raise ValueError(f"Expected {type(value)} for {key}. got {type(old_value)}")

    d[key] = value
    return old_value, value


def deep_popitem(d: MutableMapping, key: str, sep=".") -> Any:
    if sep in key:
        key, child_key = key.split(sep, 1)
        if key not in d:
            raise KeyError(f"{key}")
        if not isinstance(d[key], MutableMapping):
            raise ValueError(f"Expected MuttableMapping, got {type(d[key])}")
        return deep_popitem(d[key], child_key, sep)
    try:
        return d.pop(key)
    except KeyError:
        pass


def deep_update(dict_base: MutableMapping, other_dict: Mapping) -> MutableMapping:
    for k, v in other_dict.items():
        if k in dict_base and isinstance(dict_base[k], MutableMapping) and isinstance(v, Mapping):
            deep_update(dict_base[k], v)
        else:
            dict_base[k] = v
    return dict_base


def compare(
    subset: dict,
    superset: dict,
    *,
    ignore: set[str] | None = None,
    require: set[str] | None = None,
    exclude_values: bool = True,
) -> bool:
    subset_keys = {key for key in subset.keys() if key not in (ignore or set())}

    for key in require or set():
        if key not in subset_keys:
            return False
    if not subset_keys <= superset.keys():
        return False

    if not exclude_values:
        for key, value in subset.items():
            if key not in subset_keys:
                continue
            if superset[key] != value:
                return False
    return True


def map(root: Mapping, func: Callable) -> dict:
    """Calls a function on all of the keys in a dictionary, recursively.

    Args:
        root (Mapping): A dictionary.
        func (Callable): A function that operates on the key. This should
            return the new key.

    Returns:
        dict: A dictionary with new keys.
    """
    new_root = {}
    for k, v in root.items():
        if isinstance(v, Mapping):
            new_root[func(k)] = map(v, func)
        else:
            new_root[func(k)] = v
    return new_root


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
