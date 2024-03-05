"""
This is the main module of the library. It provides the following classes:

- ILink: An interface for link objects.
- Link: A concrete implementation of the ILink interface.
- IState: An interface for state objects.
- Machine: A class for state machine objects.
- AbstractState: An abstract base class for state objects.
- CallbackState: A class for state objects that use callbacks.

"""

from ._link import ILink, Link
from ._machine import Machine
from ._state import AbstractState, CallbackState, IState

__all__ = ["ILink", "Link", "IState", "Machine", "AbstractState", "CallbackState"]
