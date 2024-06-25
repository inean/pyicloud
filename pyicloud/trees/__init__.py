"""Library base file."""

from __future__ import annotations

import asyncio
import inspect
import types
from abc import ABC, abstractmethod
from asyncio import Runner, iscoroutine, sleep
from collections import deque
from collections.abc import Generator, Sequence
from contextlib import contextmanager
from contextvars import ContextVar, Token, copy_context
from enum import Enum
from functools import partial, wraps
from inspect import BoundArguments, Parameter, iscoroutinefunction, signature
from typing import (
    Any,
    Awaitable,
    Callable,
    ClassVar,
    Coroutine,
    Iterator,
    ParamSpec,
    Self,
    TypedDict,
    TypeVar,
    cast,
    overload,
)

from httpx import AsyncClient
from pydantic import Secret

from pyicloud.log import LOGGER, PyiCloudPasswordFilter
from pyicloud.models.cookies import Cookies
from pyicloud.models.settings import Settings
from pyicloud.paths import CookiesJar, SettingsFile


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


P = ParamSpec("P")
R = TypeVar("R")
T = TypeVar("T")


def _set_ctx_factory(
    cls: type[T], getter: Callable[[T], dict[str, Any]]
) -> Callable[[Callable[P, R]], Callable[P, R] | Callable[P, Coroutine[Any, Any, R]]]:
    """_summary_

    Args:
        cls (type[T]): _description_
        getter (Callable[[T], dict[str, Any]]): _description_

    Returns:
        Callable[[Callable[P, R]], Callable[P, R] | Callable[P, Coroutine[Any, Any, R]]]: _description_
    """

    def _set_ctx(
        func: Callable[P, R] | None = None,
        *,
        name: str | None = None,
        modifier: Callable[..., Any] | Coroutine[Any, Any, Any] | None = None,
        condition: Callable[[Any], bool] | None = None,
    ) -> Callable[P, R] | Callable[P, Coroutine[Any, Any, R]]:
        """Store response in context."""

        if func is None:
            return cast(Callable[P, R], partial(_set_ctx, name=name, modifier=modifier))

        def set_cache(cache: dict[str, Any], *, result: R) -> R:
            nonlocal name
            if name is None:
                name = func.__name__

            cache[name] = result
            return result

        @wraps(func)
        async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            assert isinstance(args[0], cls), f"First argument must be a '{cls.__name__}' instance"
            result = func(*args, **kwargs)
            if isinstance(result, Awaitable):
                result = await result
            if not callable(condition) or condition(result):
                if callable(modifier):
                    coro = result = modifier(result)
                    if iscoroutine(coro):
                        result = await coro
                result = set_cache(getter(args[0]), result=cast(R, result))
            return cast(R, result)

        @wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            assert isinstance(args[0], cls), f"First argument must be a '{cls.__name__}' instance"
            result = func(*args, **kwargs)
            if not callable(condition) or condition(result):
                if callable(modifier):
                    assert not iscoroutinefunction(modifier), "Modifier must be a synchronous function"
                    result = modifier(result)
                result = set_cache(getter(args[0]), result=cast(R, result))
            return cast(R, result)

        return async_wrapper if iscoroutinefunction(func) else wrapper

    return _set_ctx


def set_blackboard(
    func: Callable[P, R] | None = None,
    *,
    name: str | None = None,
    modifier: Callable[..., Any] | Coroutine[Any, Any, Any] | None = None,
) -> Callable[P, R]:
    return _set_ctx_factory(Tree, lambda self: self.blackboard)(func, name=name, modifier=modifier)  # type: ignore


def set_context(
    func: Callable[P, R] | None = None,
    *,
    name: str | None = None,
    modifier: Callable[..., Any] | Coroutine[Any, Any, Any] | None = None,
) -> Callable[P, R]:
    return _set_ctx_factory(BehaveTree, lambda self: self.context)(func, name=name, modifier=modifier)  # type: ignore


def _del_ctx_factory(
    cls: type[T], getter: Callable[[T], dict[str, Any]]
) -> Callable[[Callable[P, R], Sequence[str]], Callable[P, R] | Callable[P, Coroutine[Any, Any, R]]]:
    """_summary_

    Args:
        cls (type[T]): _description_
        getter (Callable[[T], dict[str, Any]]): _description_

    Returns:
        Callable[[Callable[P, R]], Callable[P, R] | Callable[P, Coroutine[Any, Any, R]]]: _description_
    """

    def _del_ctx(
        func: Callable[P, R],
        remove: Sequence[str],
    ) -> Callable[P, R] | Callable[P, Coroutine[Any, Any, R]]:
        """Delete remp from context."""

        if func is None:
            return cast(Callable[P, R], partial(_del_ctx, remove=remove))

        def delete_from_cache(cache: dict[str, Any]) -> None:
            nonlocal remove
            for entry in [remove] if isinstance(remove, str) else remove:
                cache.pop(entry, None)

        @wraps(func)
        async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            assert isinstance(args[0], cls), f"First argument must be a '{cls.__name__}' instance"
            result = func(*args, **kwargs)
            if isinstance(result, Awaitable):
                result = await result
            delete_from_cache(getter(args[0]))
            return cast(R, result)

        @wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            assert isinstance(args[0], cls), f"First argument must be a '{cls.__name__}' instance"
            result = func(*args, **kwargs)
            delete_from_cache(getter(args[0]))
            return cast(R, result)

        return async_wrapper if iscoroutinefunction(func) else wrapper

    return _del_ctx


def del_blackboard(func: Callable[P, R] | None = None, *, name: Sequence[str]) -> Callable[P, R]:
    return _del_ctx_factory(Tree, lambda self: self.blackboard)(func, name)  # type: ignore


def _use_ctx_factory(
    cls: type[T],
    getter: Callable[[T], dict[str, Any]],
) -> Callable[[Callable[P, R]], Callable[P, R] | Callable[P, Coroutine[Any, Any, R]]]:
    """_summary_

    Args:
        cls (type[T]): _description_
        getter (Callable[[T], dict[str, Any]]): _description_

    Returns:
        Callable[[Callable[P, R]], Callable[P, R] | Callable[P, Coroutine[Any, Any, R]]]: _description_
    """

    def _use_ctx(func: Callable[P, R]) -> Callable[P, R] | Callable[P, Coroutine[Any, Any, R]]:
        """Retrieve response from context and inject as function parameters."""

        def get_context(*args, **kwargs) -> dict[str, Any]:
            assert isinstance(args[0], cls), f"First argument must be a '{cls.__name__}' instance"

            # Get context and copy it to avoid modifying the original.
            context = getter(args[0]).copy()

            # Pop all arguments from the context that will be passed from kwargs
            all(context.pop(arg, None) for arg in kwargs)
            return context

        def get_args(context, *args, **kwargs) -> BoundArguments:
            # bind the function signature with the context
            sig = signature(func)

            # Determine if context holder (aka args[0]) is an instance of the first argument
            nargs = args[1:]
            if param := next(iter(sig.parameters.values()), None):
                if klass := globals().get(param.annotation, cls):
                    if isinstance(args[0], klass):
                        nargs = args

            # Skip first argument which is context
            bound = sig.bind_partial(*nargs, **kwargs)

            # Check args
            # Pass all dictionary if a kwargs is present
            if any(x.kind == Parameter.VAR_KEYWORD for x in reversed(tuple(sig.parameters.values()))):
                bound.arguments.update(context)
            # Otherwise, pass only the required arguments
            else:
                for name, value in context.items():
                    if name not in bound.arguments and name in sig.parameters:
                        bound.arguments[name] = value
            # Apply default values to the bound arguments if needed
            bound.apply_defaults()
            return bound

        @wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            context = get_context(*args, **kwargs)
            bound = get_args(context, *args, **kwargs)
            return func(*bound.args, **bound.kwargs)

        @wraps(func)
        async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            context = get_context(*args, **kwargs)
            bound = get_args(context, *args, **kwargs)
            result = func(*bound.args, **bound.kwargs)
            if isinstance(result, Awaitable):
                return await result
            return result

        return async_wrapper if iscoroutinefunction(func) else wrapper

    return _use_ctx


def use_blackboard(func: Callable[P, R]) -> Callable[P, R] | Callable[P, Coroutine[Any, Any, R]]:
    return _use_ctx_factory(Tree, lambda self: self.blackboard)(func)


def use_context(func: Callable[P, R]) -> Callable[P, R] | Callable[P, Coroutine[Any, Any, R]]:
    return _use_ctx_factory(BehaveTree, lambda self: self.context)(func)


def blackboard(
    *,
    fetch: bool = False,
    store: str
    | tuple[
        str,
        Callable[..., Any] | Coroutine[Any, Any, Any],
        Callable[[Any], bool],
    ]
    | None = None,
    remove: Sequence[str] | None = None,
):
    def decorator(func: Callable[P, R]) -> Callable[P, R] | Callable[P, Coroutine[Any, Any, R]]:
        _func: Callable[P, R] | Callable[P, Coroutine[Any, Any, R]] = func
        if fetch:
            _func = _use_ctx_factory(Tree, lambda self: self.blackboard)(_func)
        if store is not None:
            istore = iter((store,) if isinstance(store, str) else store)
            _func = _set_ctx_factory(Tree, lambda self: self.blackboard)(
                _func,
                name=next(istore),  # type: ignore
                modifier=next(istore, None),  # type: ignore
                condition=next(istore, None),  # type: ignore
            )
        if remove is not None:
            _func = _del_ctx_factory(Tree, lambda self: self.blackboard)(_func, remove=remove)  # type: ignore
        return _func

    return decorator


class Tree(ABC):
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
        context: dict[Any, Any] | None = None,
    ):
        self.settings = settings
        self.cookies = cookies or Cookies({})
        self._context = ContextVar("blackboard", default=context or {})

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

    @contextmanager
    def context(self, **blackboard) -> Iterator[Self]:
        token: Token = self._context.set(blackboard or self._context.get())
        try:
            yield self
        finally:
            self._context.reset(token)

    @property
    def client(self) -> AsyncClient:
        options = self.tree_config.get("client_options", {})
        session = self.tree_config.get("client", AsyncClient)
        return session(**options)

    @property
    def blackboard(self) -> dict[Any, Any]:
        try:
            return self._context.get()
        except LookupError as err:
            raise RuntimeError("No context available") from err

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

    @property
    @abstractmethod
    def transitions(self) -> Sequence[TreeTransitionExtra]: ...

    @property
    @abstractmethod
    def bhtree(self) -> Callable[[], Awaitable[Any]]: ...

    @abstractmethod
    def run(self, bhtree: BehaveTree, *args, **kwargs) -> tuple[Any]: ...


class TickError(Exception):
    """Error during the execution of the behavior tree."""


class TreeState(Enum):
    # Special state to match any state
    ANY = "*"
    # Unhandled error
    INVALID = "INVALID"

    # This is the initial state of the session, where no user is logged in.
    SESSION_CLOSED = "SESSION_CLOSED"
    # The system is in the process of signing in.
    SESSION_LOGGED = "SIGNIN"
    # Last sign in attempt failed.
    SIGNIN_ERROR = "SIGNIN_ERROR"
    # The session is idle, meaning a user is logged in but no tasks are being performed.
    SESSION_ACTIVE = "SESSION_ACTIVE"
    # The system is busy running a task.
    TASK_RUNNING = "TASK_RUNNING"
    # An error occurred during the execution of a task.
    TASK_ERROR = "RASK_ERROR"


# | Current State  | Action / Trigger               | Next State     |
# |----------------|--------------------------------|----------------|
# | SESSION_CLOSED | Validate Credentials (ok)      | SESSION_ACTIVE |
# | SESSION_CLOSED | Validate Credentials (expired) | SIGN_IN        |
# | SIGN_IN        | Login (successful)             | SESSION_ACTIVE |
# | SIGN_IN        | Login (failed)                 | SIGNIN_ERROR   |
# | SIGNIN_ERROR   | backoff                        | SESSION_CLOSED |
# --------------------------------------------------------------------
# | SESSION_ACTIVE | Run task (sync)                | SESSION_ACTIVE |
# | SESSION_ACTIVE | Run task (async)               | TASK_RUNNING   |
# | SESSION_ACTIVE | Run task with session expired  | SESSION_CLOSED |
# | TASK_RUNNING   | Task finished                  | SESSION_ACTIVE |
# | TASK_RUNNING   | Error occurred                 | TASK_ERROR     |
# | TASK_ERROR     | Error resolved                 | SESSION_ACTIVE |
# | TASK_ERROR     | Session reset / expired        | SIGN_IN        |


class TreeTransition(TypedDict):
    # Event that triggers the transition
    trigger: str | Sequence[str]
    # Initial state of the tree
    source: TreeState
    # Final state of the tree
    dest: TreeState
    # Action to be executed
    action: object | Callable[..., Awaitable[Any]] | None


class TreeTransitionExtra(TreeTransition, total=False):
    # Error State
    error: TreeState | None
    # Callable to be executed on error
    on_error: Callable[[Exception], tuple[TreeAction, Exception | Any]] | None

    # Whereher context stored values should be passed as args to the action if needed
    use_context: bool | None

    # Store result in context with name
    result: str | None
    # When result is used, callable to process result before store
    on_result: Callable[[Any], Any] | None


def with_context_once(func: Callable[P, R]) -> Callable[P, R]:
    @wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs):
        self = cast(BehaveTree, args[0])
        if self._token is not None:
            return func(*args, **kwargs)
        with self:
            return func(*args, **kwargs)

    return wrapper


def shortest_path(graph, start, end):
    queue = deque([[start]])
    visited = set()

    while queue:
        path = queue.popleft()
        state = path[-1]

        # Special case to match any state
        if state == TreeState.ANY:
            return path
        if state == end:
            return path

        elif state not in visited:
            for next_state in graph.get(state, []):
                new_path = list(path)
                new_path.append(next_state)
                queue.append(new_path)

            visited.add(state)

    return None


class ExponentialBackoff:
    def __init__(self, base=2, initial_delay=3):
        self.base = base
        self.current_delay = initial_delay

    async def backoff(self):
        LOGGER.info(f"Sleeping for {self.current_delay} seconds")
        await sleep(self.current_delay)
        self.current_delay *= self.base


class BehaveTree:
    class _FakeTree:
        @contextmanager
        def context(self, **blackboard) -> Iterator[Self]:
            yield self

    transitions: Sequence[TreeTransition] = [
        {
            "trigger": "reset",
            "source": TreeState.ANY,
            "dest": TreeState.SESSION_CLOSED,
            "action": None,
        },
        {
            "trigger": "backoff",
            "source": TreeState.ANY,
            "dest": TreeState.TASK_RUNNING,
            "action": ExponentialBackoff(),
        },
    ]

    def __init__(self, *, transitions: Sequence[TreeTransition] | None = None):
        self._runner: Runner = Runner()
        self._context: ContextVar[dict[str, Any]] = ContextVar("ctx")
        self._token: Token | None = None
        self._status: TreeState = TreeState.SESSION_CLOSED
        self._transitions: Sequence[TreeTransition] = list(self.transitions)
        if transitions:
            self._transitions.extend(transitions)

        # Init states dictionary
        self._states: dict[TreeState, list[TreeState]] = {}
        for valid_state in TreeState:
            self._states[valid_state] = []

        # Populate states dictionary
        for transition in self._transitions:
            source, dest = transition["source"], transition["dest"]
            assert dest not in self._states[source], f"Duplicate transition from '{source}' to '{dest}'"
            self._states[source].append(dest)

        # Handle transitions with ANY state
        any_states = self._states.pop(TreeState.ANY, [])
        for valid_state in TreeState:
            if valid_state is not TreeState.ANY:
                self._states[valid_state].extend(any_states)

    def __getattr__(self, name: str):
        for transition in self._transitions:
            trigger = transition["trigger"]
            trigger = trigger if isinstance(trigger, tuple) else (trigger,)
            if name in trigger:
                return partial(self.tick, transition)
        raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")

    def __enter__(self):
        self._runner.__enter__()
        self._token = self._context.set({})
        self._status = TreeState.SESSION_CLOSED
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._status = TreeState.SESSION_CLOSED
        self._context.reset(cast(Token, self._token))
        self._runner.close()

    def run(
        self,
        transitions: Sequence[TreeTransition],
        *,
        context: dict[str, Any] | None = None,
        **data,
    ) -> Sequence[Any]:
        results = []
        for transition in transitions:
            result = self.tick(transition, context=context, **data)
            results.extend(result)
        return results

    @with_context_once
    def tick(self, transition: TreeTransition, *, context: dict[str, Any] | None = None, **data) -> Sequence[Any]:
        # Ensure a valid path exists from the current state to the target state
        def compute_path(transition: TreeTransition) -> list[TreeState]:
            assert self._status is not TreeState.INVALID, "Invalid state"

            start, end = self._status, transition["source"]
            if not (path := shortest_path(self._states, start, end)):
                raise TickError(f"Invalid path from '{start}' to '{end}'")
            return cast(list[TreeState], path)

        # Find all transitions that match the current state and target state
        def find_transition(source: TreeState, dest: TreeState) -> Generator[TreeTransition, None, None]:
            for t in self._transitions:
                if t["source"] not in (TreeState.ANY, source):
                    continue
                if t["dest"] is not dest:
                    continue
                yield t

        # When transition is invoked with 'to_', we jump directly to the target state
        # otherwise iterate over all available states and is a valid path is fund,
        # run all actions till target state is reached
        def run_action(transition: TreeTransition, **data) -> Any:
            if (action := transition["action"]) is None:
                return None

            if not isinstance(action, (types.FunctionType, types.MethodType)):
                trigger = transition["trigger"]
                trigger = trigger if isinstance(trigger, str) else trigger[0]
                action = getattr(action, trigger)

            assert callable(action), f"Invalid action type: {type(action)}"

            # We need to create a fake tree for non
            # tree actions. This is needed to be able to use the context variables in the action
            model = cast(Tree, action.__self__) if inspect.ismethod(action) else self._FakeTree()

            # Allow to use context vartiables to pass arguments to the action,
            # and store result for later use
            action = use_context(action) if transition.get("use_context", True) else action

            # Compute a default store name if not provided
            ctxnme = transition["trigger"]
            ctxnme = transition.get("result", ctxnme if isinstance(ctxnme, str) else ctxnme[0])
            # Only store result if requested by transition
            if "result" in transition or "on_result" in transition:
                action = set_context(action, name=ctxnme, modifier=transition.get("on_result", None))

            # Run the action and store the result. If its a tree, run it within model context
            # with context updated from the BhTree context
            with model.context(**self.context):
                result = coro = action(self, **data)
                if iscoroutine(coro):
                    result = self.runner.run(coro, context=copy_context())
                return result

        # Update context with new data passed to the tick method. On tick exit, context will be discarded
        self.context.update(context or {})

        result: list[Any] = []
        # Otherwise, we need to find a valid path from the current state to the target state
        while path := compute_path(transition):
            # Parse states and ensure the first state is the current state
            assert self._status == path.pop(0)
            init_state = self._status
            fini_state = path[0] if path else transition["dest"]

            # Find next transition to run
            candidates = find_transition(init_state, fini_state)
            if (next_transition := transition if not path else next(candidates, None)) is None:
                raise TickError(f"Invalid transition from '{init_state}' to '{fini_state}'")

            # Run the action
            try:
                value = run_action(next_transition, **data)
                # Parse result
                if "error" in next_transition:
                    fini_state = next_transition["error"]
                if "on_error" in next_transition:
                    value = next_transition["on_error"](value)
                # update state
                self._status = fini_state
                result.append(value)

            except Exception as err:
                # Behavior tree can handle errors in a custom way. By default,
                # it will raise the exception
                action, value = self.on_error(next_transition, result, err)
                # Exception path
                if action is TreeAction.FAIL:
                    LOGGER.error(f"Error in '{transition['trigger']}' transition: {err}")
                    assert isinstance(value, Exception), f"Invalid Exception type for '{value}'"
                    raise value from err
                # Exit path
                if action is TreeAction.EXIT:
                    assert isinstance(value, Sequence), f"Invalid value type for '{value}'"
                    LOGGER.error(f"Exiting '{transition['trigger']}' transition: {value}")
                    return cast(tuple[Any], value)

            # Exit if we reached the target state
            if next_transition == transition:
                break

        return result

    def on_error(
        self, transtion: TreeTransition, result: Sequence[Any], err: Exception
    ) -> tuple[TreeAction, Exception | Any]:
        return TreeAction.FAIL, err

    @property
    def state(self) -> TreeState:
        return self._status

    @property
    def runner(self) -> Runner:
        assert self._context is not None, "Context is not initialized"
        return self._runner

    @property
    def context(self) -> dict[str, Any]:
        assert self._context is not None, "Context is not initialized"
        return self._context.get()
