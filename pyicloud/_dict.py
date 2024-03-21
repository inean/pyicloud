"""Dictiory related operations"""


def flatten(d, parent_key="", sep="."):
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten(v, new_key, sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def unflatten(key, value, sep="."):
    if sep not in key:
        return {key: value}
    key, child_key = key.split(sep, 1)
    return {key: unflatten(child_key, value, sep)}


def deep_getitem(d, key, sep="."):
    if sep in key:
        key, child_key = key.split(sep, 1)
        if key not in d:
            raise KeyError(f"{key}")
        if not isinstance(d[key], dict):
            raise ValueError(f"Expected dict got {type(d[key])}")
        return deep_getitem(d[key], child_key, sep)

    if key not in d:
        raise KeyError(f"{key}")
    return d[key]


def deep_setitem(d, key, value, sep="."):
    if sep in key:
        key, child_key = key.split(sep, 1)
        if key not in d:
            raise KeyError(f"{key}")
        if not isinstance(d[key], dict):
            raise ValueError(f"Expected dict {key}. got {type(d[key])}")
        return deep_setitem(d[key], child_key, value, sep)

    old_value = d.get(key, type(value)())
    # Be flexible with the type of the value. Allow None or falsy values
    if old_value and value and not isinstance(value, type(old_value)):
        raise ValueError(f"Expected {type(value)} for {key}. got {type(old_value)}")

    d[key] = value
    return old_value, value


def deep_popitem(d, key, sep="."):
    if sep in key:
        key, child_key = key.split(sep, 1)
        if key not in d:
            raise KeyError(f"{key}")
        if not isinstance(d[key], dict):
            raise ValueError(f"Expected dict got {type(d[key])}")
        return deep_popitem(d[key], child_key, sep)
    try:
        d.pop(key)
    except KeyError:
        pass
