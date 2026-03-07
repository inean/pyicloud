"""Compatibility module forwarding imports to pyicloud.platform.legacy_auth_tree.session."""

from __future__ import annotations

import importlib
import sys

_CANONICAL_MODULE = "pyicloud.platform.legacy_auth_tree.session"

sys.modules[__name__] = importlib.import_module(_CANONICAL_MODULE)
