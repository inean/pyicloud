"""Library base file."""

from __future__ import annotations

from abc import ABC, abstractmethod
from asyncio import Runner
from contextlib import contextmanager
from contextvars import Context, ContextVar, Token, copy_context
from enum import Enum
from functools import partial, wraps
from inspect import BoundArguments, iscoroutinefunction, signature
from typing import (
    Any,
    Awaitable,
    Callable,
    ClassVar,
    Coroutine,
    Generic,
    Iterator,
    ParamSpec,
    TypedDict,
    TypeVar,
    cast,
)

import async_btree as bt
from httpx import AsyncClient
from pydantic import Secret

from pyicloud.log import PyiCloudPasswordFilter
from pyicloud.models.cookies import Cookies
from pyicloud.models.settings import Settings
from pyicloud.paths import CookiesJar, SettingsFile

P = ParamSpec("P")
R = TypeVar("R")


class TreeAction(Enum):
    CONTINUE = "CONTINUE"
    EXIT = "EXIT"  # Catch the exception and return the value
    FAIL = "FAIL"  # An exception will be raised


class TreeConfig(TypedDict, total=False):
    """
    Configuration for the behavior tree.
    """

    client: type[AsyncClient] | Callable[..., AsyncClient]
    """Type of HTTPX Async client."""

    client_options: dict[str, Any]
    """Options for the HTTPX Async client, represented as a dictionary of strings to any value."""


class ModelTree(ABC):
    __slots__ = ("settings", "cookies", "_context")

    cookies: Cookies
    """Cookies for the model."""

    settings: Settings
    """Settings for the model."""

    tree_config: ClassVar[TreeConfig] = {}
    """Configuration for the behavior tree."""

    _context: ContextVar[dict[Any, Any]]
    """Context variable for the blackboard pattern."""

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)

        new_config = TreeConfig(
            client=AsyncClient,
            client_options={},
        )
        new_config.update(kwargs.get("tree_config", cls.tree_config or {}))
        cls.tree_config = new_config

    def __init__(
        self,
        *,
        settings: Settings,
        cookies: Cookies | None = None,
    ):
        self.settings = settings
        self.cookies = cookies or Cookies({})
        self._context = ContextVar("blackboard")

        # Add a filter so password is not logged
        PyiCloudPasswordFilter.register(self.settings)
        self.settings.account.events.password.connect(
            partial(PyiCloudPasswordFilter.on_changed_password, context=self.settings)
        )

        # Listen to username updates and reload config if necessary
        self.settings.account.events.username.connect(
            lambda u: SettingsFile(self.settings).loads(),
        )
        self.settings.account.events.username.connect(
            lambda u: CookiesJar(self.cookies).loads(username=u),
        )

        # Emit to force reload
        assert self.settings.account.username, "Username is required"
        self.settings.account.events.username.emit(self.settings.account.username)

        return self

    @property
    def client(self) -> AsyncClient:
        options = self.tree_config.get("client_options", {})
        session = self.tree_config.get("client", AsyncClient)
        return session(**options)

    @contextmanager
    def context(self, initial_data: dict[Any, Any] | None = None) -> Iterator[None]:
        token: Token = self._context.set({} if initial_data is None else initial_data.copy())
        yield
        self._context.reset(token)

    @property
    def blackboard(self) -> dict[Any, Any]:
        try:
            return self._context.get()
        except LookupError as err:
            raise RuntimeError("No context available") from err

    @staticmethod
    def set_context(
        func: Callable[P, R] | None = None,
        *,
        name: str | None = None,
    ) -> Callable[P, R]:
        """Store response in context."""

        if func is None:
            return cast(Callable[P, R], partial(ModelTree.set_context, name=name))

        def set_cache(self: ModelTree, *, result: R) -> R:
            nonlocal name
            if name is None:
                name = func.__name__

            self.blackboard[name] = result
            return result

        @wraps(func)
        async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            self = cast(ModelTree, args[0])
            result = func(*args, **kwargs)
            if isinstance(result, Awaitable):
                result = await result
            set_cache(self, result=cast(R, result))
            return cast(R, result)

        @wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            self = cast(ModelTree, args[0])
            result = func(*args, **kwargs)
            set_cache(self, result=cast(R, result))
            return cast(R, result)

        return cast(Callable[P, R], async_wrapper if iscoroutinefunction(func) else wrapper)

    @staticmethod
    def with_context(func: Callable[P, R]) -> Callable[P, R]:
        """Retrieve response from context and inject as function parameters."""

        def get_cache(*args: P.args, **kwargs: P.kwargs) -> BoundArguments:
            sig = signature(func)
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()

            self = cast(ModelTree, args[0])
            for name in bound.arguments.keys():
                if name in self.blackboard:
                    bound.arguments[name] = self.blackboard[name]

            return bound

        @wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            bound = get_cache(*args, **kwargs)
            return func(*bound.args, **bound.kwargs)

        @wraps(func)
        async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            bound = get_cache(*args, **kwargs)
            result = func(*bound.args, **bound.kwargs)
            if isinstance(result, Awaitable):
                return await result
            return result

        return cast(Callable[P, R], async_wrapper if iscoroutinefunction(func) else wrapper)

    @property
    def username(self) -> str:
        """Username getter."""
        return self.settings.account.username

    @property
    def password(self) -> str | None:
        """Password getter."""
        password = self.settings.account.password
        return cast(Secret, password).get_secret_value() if password else None

    @password.setter
    def password(self, value):
        self.settings.account.password = value

    @property
    def apple_id(self) -> str:
        """Apple ID getter."""
        return self.username

    def __str__(self):
        return f"TreeModel for: ({self.username})"

    def __repr__(self):
        return f"<{self}>"


T = TypeVar("T", bound=ModelTree)


class BehaveTree(ABC, Generic[T]):
    def __init__(self, *, model: T, **kwargs):
        self._model: T = model
        self._btree: Callable[..., Coroutine[Any, Any, Any]] | None = None

        self._kernel: Runner | None = None
        self._context: Context | None = None

    @contextmanager
    def context(self):
        with self._model.context(), Runner() as self._kernel:
            self._context = copy_context()
            self._btree = self._setup()
            try:
                yield self
            finally:
                self._btree = None
                self._kernel = None
                self._context = None

    @staticmethod
    def use_contextmanager(func: Callable[P, R]) -> Callable[P, R]:
        @wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs):
            self = cast(BehaveTree, args[0])
            if self._btree:
                return func(*args, **kwargs)
            with self.context():
                return func(*args, **kwargs)

        return wrapper

    @use_contextmanager
    def run(self, *args, **kwargs) -> Any:
        assert self._btree, "Tree is not setup"

        while True:
            try:
                coro = self._btree(*args, **kwargs)
                return cast(Runner, self._kernel).run(coro, context=self._context)
            except Exception as err:
                action, value = self._on_error(err)
                if action is TreeAction.FAIL:
                    raise cast(Exception, value) from err
                if action is TreeAction.EXIT:
                    return cast(Any, value)

    @use_contextmanager
    def analyze(self, indent: int = 0, label: str | None = None) -> str:
        return bt.stringify_analyze(bt.analyze(self._btree), indent, label)

    def _on_error(self, err: Exception) -> tuple[TreeAction, Exception | Any | None]:
        return TreeAction.FAIL, err

    @abstractmethod
    def _setup(self): ...

    @property
    def tree(self):
        assert self._btree, "Tree is not setup"
        return self._btree
