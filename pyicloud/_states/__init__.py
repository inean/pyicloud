"""
This is the main module of the library. It provides the following classes:

- ILink: An interface for link objects.
- Link: A concrete implementation of the ILink interface.
- IState: An interface for state objects.
- Machine: A class for state machine objects.
- AbstractState: An abstract base class for state objects.
- CallbackState: A class for state objects that use callbacks.

"""

from ._link import ConditionalLink, ILink, Link, RetryLink
from ._machine import Machine
from ._state import AbstractState, CallbackState, ContextState, IState

__all__ = [
    "ILink",
    "Link",
    "RetryLink",
    "ConditionalLink",
    "IState",
    "Machine",
    "AbstractState",
    "CallbackState",
    "ContextState",
]
