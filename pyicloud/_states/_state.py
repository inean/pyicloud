import asyncio
import inspect
from typing import Any, Callable

from ._interfaces import IState


class AbstractState(IState):
    def __init__(self, name: str | None = None, debug=True):
        self._name = name or type(self).__name__
        self._debug = debug
        self._links = []

    @property
    def name(self):
        return self._name

    def enter(self):
        pass

    async def execute(self):
        self.log_current_state()
        await asyncio.sleep(0)

    def exit(self):
        pass

    def add_link(self, link):
        if link not in self._links:
            self._links.append(link)

    def remove_link(self, link):
        if link in self._links:
            self._links.remove(link)

    def remove_all_links(self):
        self._links.clear()

    def validate_links(self):
        for link in self._links:
            next_state = link.validate()
            if next_state is not None:
                return next_state
        return None

    def enable_links(self):
        for link in self._links:
            link.enable()

    def disable_links(self):
        for link in self._links:
            link.disable()

    def log_current_state(self):
        if self._debug:
            print(f"Current state = {self._name}")


class ContextState(AbstractState):
    def __init__(self, context: Any = None, name: str | None = None, debug=False):
        AbstractState.__init__(self, name, debug)
        self._context = context

    @property
    def context(self):
        return self._context

    @context.setter
    def context(self, context):
        self._context = context


class CallbackState(ContextState):
    def __init__(self, on_execute: Callable, context: Any = None, name: str | None = None, debug=False):
        ContextState.__init__(self, context, name, debug)
        self._on_execute = on_execute

    async def execute(self):
        await asyncio.sleep(0)
        self.log_current_state()
        # Invokes the on_execute callable if it exists
        if self._on_execute is not None:
            if inspect.iscoroutinefunction(self._on_execute):
                await self._on_execute()
            else:
                self._on_execute()
