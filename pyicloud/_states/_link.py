from ._interfaces import ILink


class AbstractLink(ILink):
    def __init__(self, next_state):
        self._next_state = next_state

    def validate(self):
        return self._next_state


class Link(AbstractLink):
    def __init__(self, next_state):
        super().__init__(next_state)
        self._enabled = True

    def enable(self):
        self._enabled = True

    def disable(self):
        self._enabled = False

    def validate(self):
        return self._next_state if self._enabled else None


class RetryLink(Link):
    def __init__(self, next_state, retries=3):
        super().__init__(next_state)
        self._max_retries = retries
        self._retries = 0

    def validate(self):
        if self._retries < self._max_retries:
            self._retries += 1
            return self._next_state
        return None


class ConditionalLink(Link):
    def __init__(self, next_state, condition):
        super().__init__(next_state)
        self._condition = condition

    def validate(self):
        return self._next_state if self._condition() else None


class EventLink(AbstractLink):

    class ActionWrapper:
        def __init__(self, subscribe, unsubscribe):
            self.subscribe = subscribe
            self.unsubscribe = unsubscribe

    def __init__(self, next_state, action_wrapper):
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
