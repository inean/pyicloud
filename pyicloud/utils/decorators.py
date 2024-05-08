import functools
import warnings
from typing import Callable, ParamSpec, Type, TypeVar, cast, overload

P = ParamSpec("P")
R = TypeVar("R")
C = TypeVar("C")


@overload
def deprecated(entity: Type[C]) -> Type[C]: ...


@overload
def deprecated(entity: Callable[P, R], *, message: str | None = None) -> Callable[P, R]: ...


def deprecated(
    entity: Callable[P, R] | Type[C] | None = None,
    *,
    message: str | None = None,
) -> Callable[P, R] | Type[C]:
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


R = TypeVar("R")


def classproperty(func: Callable[..., R]) -> R:
    return classmethod(property(func))  # type: ignore
