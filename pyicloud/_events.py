class Events:
    def __init__(self, events, allow_duplicates=True):
        self._events = {event: [] for event in events}

    def subscribe(self, event_name, func):
        if event_name not in self._events:
            raise ValueError(f"No such event: {event_name}")
        if func in self._events[event_name]:
            raise ValueError(f"Function already subscribed to event: {event_name}")
        self._events[event_name].append(func)

    def unsubscribe(self, event_name, func):
        if event_name not in self._events:
            raise ValueError(f"No such event: {event_name}")
        if func not in self._events[event_name]:
            raise ValueError(f"Function not subscribed to event: {event_name}")
        self._events[event_name].remove(func)

    def fire(self, event_name, *args, **kwargs):
        if event_name not in self._events:
            raise ValueError(f"No such event: {event_name}")
        for subscriber in self._events[event_name]:
            subscriber(*args, **kwargs)
