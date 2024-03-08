from abc import ABC, abstractmethod


class ILink(ABC):
    @abstractmethod
    def validate(self) -> "IState":
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
