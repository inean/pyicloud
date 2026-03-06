"""Compatibility package forwarding imports to pyicloud.interfaces.cli."""

from pyicloud.interfaces import cli as _canonical_cli

__path__ = _canonical_cli.__path__
