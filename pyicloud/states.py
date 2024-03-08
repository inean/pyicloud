"""State module for the PyiCloud API."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ._states import ContextState, IState, Machine
from .config import PyiCloudFileConfig as Config


# States
class Disconnected(ContextState):
    """Account is disconnected. Transition to:
    - Verified: If there's session data and required HSA tokens
    - Logged: If there's session data but HSA tokens are missing.
    - SignIn: When a password is provided to context
    """


class SignIn(ContextState):
    """State when the user is not authenticated yet. Transition to:
    - Logged: When the user is authenticated.
    - Sigin: When provided password is wrong.
    """


class Logged(ContextState):
    """State when the user is authenticated. Transition to:
    - Verify: When the user has 2FA enabled.
    - VerifyFrom: When the user has 2SA enabled.
    """

    def is_signed(self) -> bool:
        """Returns True if the user is logged."""
        print("Already authenticated.", False)
        return False


class Verify(ContextState):
    """State to verify user account using a Pin Code. Transition to:
    - Verified: When pin is valid
    - Disconnected: Otherwise
    """

    def sigin(self) -> None:
        """Authenticate method."""
        print("Already authenticated.")


class VerifyFrom(ContextState):
    """State to decide wheter send verification code. Transition to:
    - VerifyWith: When a valid device has been selected
    - Disconnected: Otherwise
    """


class VerifyWith(ContextState):
    """State to verify pin code from 2SA. Transition to:
    - verified: When pin is valid
    - Disconnexted: Otherwise
    """

    def sigin(self) -> None:
        """Authenticate method."""
        print("Already authenticated.")


class Verified(ContextState):
    """Authorized state class for the PyiCloud API."""

    def sigin(self) -> None:
        """Authenticate method."""
        print("Already authenticated.")


class Account(ABC):
    """Account class for the PyiCloud API."""

    machine = Machine()

    _disconnected: IState
    _signin: IState
    _logged: IState
    _verify: IState
    _verify_from: IState
    _verify_with: IState
    _verified: IState

    def __init__(self, user: str, password: str, config: Config) -> None:
        self._user = user
        self._password = password
        self._config = config
        self._state = None

        # Init Machine
        self._set_states()
        self._set_links()

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
