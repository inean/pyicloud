import asyncio
import inspect
from abc import ABC, abstractmethod

from ._link import ILink


class IState(ABC):
    @abstractmethod
    def enter(self):
        raise NotImplementedError

    @abstractmethod
    async def execute(self):
        raise NotImplementedError

    @abstractmethod
    def exit(self):
        raise NotImplementedError

    @abstractmethod
    def add_link(self, link: ILink):
        raise NotImplementedError

    @abstractmethod
    def remove_link(self, link: ILink):
        raise NotImplementedError

    @abstractmethod
    def remove_all_links(self):
        raise NotImplementedError

    @abstractmethod
    def validate_links(self):
        raise NotImplementedError

    @abstractmethod
    def enable_links(self):
        raise NotImplementedError

    @abstractmethod
    def disable_links(self):
        raise NotImplementedError


class AbstractState(IState):
    def __init__(self, name="State", debug=False):
        self._name = name
        self._debug = debug
        self._links = []

    def enter(self):
        pass

    async def execute(self):
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
            print(f"Current state = {self._name}({type(self).__name__})")


class ContextState(AbstractState):
    def __init__(self, name="State", context=None, debug=False):
        AbstractState.__init__(self, name, debug)
        self._context = context

    @property
    def context(self):
        return self._context

    @context.setter
    def context(self, context):
        self._context = context


class CallbackState(ContextState):
    def __init__(self, name="State", on_execute=None, context=None, debug=False):
        ContextState.__init__(self, name, context, debug)
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
