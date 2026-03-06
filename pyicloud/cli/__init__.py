"""Compatibility package forwarding imports to pyicloud.interfaces.cli."""

import sys

from pyicloud.interfaces import cli as _canonical_cli

sys.modules[__name__] = _canonical_cli
