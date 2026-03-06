from __future__ import annotations

import functools
import warnings
from collections.abc import Callable
from typing import Any, ParamSpec, TypeVar, cast, overload

P = ParamSpec("P")
R = TypeVar("R")
C = TypeVar("C")


@overload
def deprecated(entity: type[C]) -> type[C]: ...


@overload
def deprecated(entity: Callable[P, R], *, message: str | None = None) -> Callable[P, R]: ...


def deprecated(
    entity: Callable[P, R] | type[C] | None = None,
    *,
    message: str | None = None,
) -> Callable[P, R] | type[C]:
    """Decorator to mark functions or classes as deprecated."""

    if entity is None:
        return cast(Callable[P, R], functools.partial(deprecated, message=message))

    if isinstance(entity, type):
        # If the obj is a class, decorate its __init__ method
        orig_init = entity.__init__

        def new_init(self, *args: P.args, **kwargs: P.kwargs) -> None:
            msg = f"Class {entity.__name__} is deprecated. {message or ''}"
            warnings.warn(msg, category=DeprecationWarning, stacklevel=2)
            orig_init(self, *args, **kwargs)

        entity.__init__ = new_init
        return entity

    elif callable(entity):
        # If the obj is a function or method, decorate it
        @functools.wraps(entity)
        def new_func(*args: P.args, **kwargs: P.kwargs) -> R:
            msg = f"Function or method {entity.__name__} is deprecated. {message or ''}"
            warnings.warn(msg, category=DeprecationWarning, stacklevel=2)
            return entity(*args, **kwargs)

        return new_func


class Deprecated(type):
    """Metaclass to deprecate all methods of a class."""

    def __init__(cls, name, bases, attrs):
        for attr_name, attr_value in attrs.items():
            if callable(attr_value):
                setattr(cls, attr_name, deprecated(attr_value))
        super().__init__(name, bases, attrs)


class classproperty(property):
    def __get__(self, instance: Any, owner: type[Any] | None = None):
        if owner is None:
            owner = type(instance)
        return cast(Callable[[type[Any]], Any], self.fget)(owner)


__all__ = ["Deprecated", "classproperty", "deprecated"]
