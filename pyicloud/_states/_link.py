from abc import ABC, abstractmethod

from _state import IState


class ILink(ABC):
    @abstractmethod
    def validate(self) -> IState:
        """The owner state-machine calls this method to examine the link and determines if it's open for transition.
        The state-machine will transit to the next state determined by the first open link of the current state.
        If all links of the state return None, the state-machine remains in the current state.

        Returns:
            The next state that this link points to, or None if the link is not open for transition.
        """
        raise NotImplementedError

    @abstractmethod
    def enable(self):
        """Activates the link."""
        raise NotImplementedError

    @abstractmethod
    def disable(self):
        """Deactivates the link."""
        raise NotImplementedError


class Link(ILink):
    def __init__(self, next_state):
        self._next_state = next_state

    def validate(self):
        return self._next_state


class EventLink(ILink):

    class ActionWrapper:
        def __init__(self, subscribe, unsubscribe):
            self.subscribe = subscribe
            self.unsubscribe = unsubscribe

    def __init__(self, action_wrapper, next_state):
        self.next_state = next_state
        self.action_wrapper = action_wrapper
        self.event_raised = False

    def validate(self):
        return self.next_state if self.event_raised else None

    def on_event_raised(self):
        self.event_raised = True

    def enable(self):
        self.action_wrapper.subscribe(self.on_event_raised)
        self.event_raised = False

    def disable(self):
        self.action_wrapper.unsubscribe(self.on_event_raised)
        self.event_raised = False
