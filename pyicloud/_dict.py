"""Dictiory related operations"""


def flatten(d, parent_key="", sep="."):
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def deep_get(d, key, sep="."):
    if sep in key:
        key, child_key = key.split(sep, 1)
        if key not in d:
            raise KeyError(f"{key}")
        if not isinstance(d[key], dict):
            raise ValueError(f"Expected dict got {type(d[key])}")
        return deep_get(d[key], child_key)

    if key not in d:
        raise KeyError(f"{key}")
    return d[key]


def deep_set(d, key, value, sep="."):
    if sep in key:
        key, child_key = key.split(sep, 1)
        if key not in d:
            raise KeyError(f"{key}")
        if not isinstance(d[key], dict):
            raise ValueError(f"Expected dict got {type(d[key])}")
        return deep_set(d[key], child_key, value)

    if key not in d:
        raise KeyError(f"{key}")
    if not isinstance(value, type(d[key])):
        raise ValueError(f"Expected {type(value)} got {type(d[key])}")

    d[key], old_value = value, d[key]
    return old_value, value


def deep_pop(d, key, sep="."):
    if sep in key:
        key, child_key = key.split(sep, 1)
        if key not in d:
            raise KeyError(f"{key}")
        if not isinstance(d[key], dict):
            raise ValueError(f"Expected dict got {type(d[key])}")
        return deep_pop(d[key], child_key)

    if key not in d:
        raise KeyError(f"{key}")
    return d.pop(key)
