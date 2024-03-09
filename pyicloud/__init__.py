"""The pyiCloud library."""

import logging

# Set up logging for this module
logging.getLogger(__name__).addHandler(logging.NullHandler())

from .base import PyiCloud, PyiCloudServices

__all__ = ["PyiCloud", "PyiCloudServices"]

# Try to import the version number from the _version module.
# If it's not available (e.g., during development), default to "dev".
try:
    from ._version import version  # type: ignore
except ImportError:
    version = "0.1"

__version__ = version
