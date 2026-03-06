"""Compatibility package forwarding imports to pyicloud.interfaces.api."""

from pyicloud.interfaces import api as _canonical_api
from pyicloud.interfaces.api import create_app

__all__ = ["create_app"]
__path__ = _canonical_api.__path__
