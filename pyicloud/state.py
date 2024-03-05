"""State module for the PyiCloud API."""

from __future__ import annotations

from abc import ABC, abstractmethod

from _states import AbstractState, Link, Machine


class Config:
    """Config class for the PyiCloud API."""


class Link(ABC):
    """Link class for the PyiCloud API."""

    @abstractmethod
    def validate(self) -> State:
        """Validate method."""
        pass

    @abstractmethod
    def enable(self) -> None:
        """Enable method."""
        pass

    @abstractmethod
    def disable(self) -> None:
        """Disable method."""
        pass


# IState
class State(ABC):
    """State class for the PyiCloud API."""

    @property
    def account(self) -> Account:
        """Account property."""
        return self._account

    @account.setter
    def account(self, account: Account) -> None:
        self._account = account

    @abstractmethod
    async def enter(self) -> None:
        """This method is called when a GameObject first enters a particular state. Use this for setup, initializing variables, etc."""
        pass

    @abstractmethod
    async def exit(self) -> None:
        """This method is called when the object leaves this state. It’s useful for cleanup, resetting variables, etc."""
        pass


# States
class Disconnected(State):
    """Account is disconnected. Transition to:
    - Verified: If there's session data and required HSA tokens
    - Logged: If there's session data but HSA tokens are missing.
    - SignIn: When a password is provided to context
    """


class SignIn(State):
    """State when the user is not authenticated yet. Transition to:
    - Logged: When the user is authenticated.
    - Sigin: When provided password is wrong.
    """

    def sigin(self) -> None:
        print("Logging in...")


class Logged(State):
    """State when the user is authenticated. Transition to:
    - Verify: When the user has 2FA enabled.
    - VerifyFrom: When the user has 2SA enabled.
    """

    def sigin(self) -> None:
        """Authenticate method."""
        print("Already authenticated.")


class Verify(State):
    """State to verify user account using a Pin Code. Transition to:
    - Verified: When pin is valid
    - Disconnected: Otherwise
    """

    def sigin(self) -> None:
        """Authenticate method."""
        print("Already authenticated.")


class VerifyFrom(State):
    """State to decide wheter send verification code. Transition to:
    - VerifyWith: When a valid device has been selected
    - Disconnected: Otherwise
    """


class VerifyWith(State):
    """State to verify pin code from 2SA. Transition to:
    - verified: When pin is valid
    - Disconnexted: Otherwise
    """

    def sigin(self) -> None:
        """Authenticate method."""
        print("Already authenticated.")


class Verified(State):
    """Authorized state class for the PyiCloud API."""

    def sigin(self) -> None:
        """Authenticate method."""
        print("Already authenticated.")


class Machine:
    """Decides next state for the PyiCloud API."""

    def __init__(self) -> None:
        self._state: State = None

    def step(self) -> None:
        """Step method."""
        self._state.execute()

    def run(self) -> None:
        """Run method."""
        self._state.enter()
        while True:
            self.step()
        self._state.exit()

    def skip(self) -> None:
        """Skip method."""
        self._state.exit()
        self._state = self._state.next


class Account(ABC):
    """Account class for the PyiCloud API."""

    machine = Machine()

    _disconnected: State
    _sigin: State
    _logged: State
    _verify: State
    _verify_from: State
    _verify_with: State
    _verified: State

    def __init__(self, user: str, password: str, config: Config = Config()) -> None:
        self._user = user
        self._password = password
        self._config = config
        self._state = None

    @abstractmethod
    def _set_states(self):
        """Set states for the account."""

    @abstractmethod
    def _set_links(self):
        """Set links between states."""

    @abstractmethod
    def on_signin(self) -> str:
        """Returns password for the account."""

    @abstractmethod
    def on_verify(self) -> str:
        """Returns pin for the account."""

    @abstractmethod
    def on_verify_from(self, devices: tuple) -> int:
        """Returns index of de device to be used for 2FA"""
