"""Compatibility package forwarding imports to pyicloud.interfaces.api."""

import sys

from pyicloud.interfaces import api as _canonical_api

sys.modules[__name__] = _canonical_api
