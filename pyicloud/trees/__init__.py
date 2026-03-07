"""Compatibility package forwarding imports to pyicloud.platform.legacy_auth_tree."""

from __future__ import annotations

import importlib
import sys

_CANONICAL_ROOT = "pyicloud.platform.legacy_auth_tree"
_canonical_trees = importlib.import_module(_CANONICAL_ROOT)

sys.modules[__name__] = _canonical_trees

_SUBMODULES = (
    "engine",
    "session",
    "setup",
)

for suffix in _SUBMODULES:
    sys.modules[f"{__name__}.{suffix}"] = importlib.import_module(f"{_CANONICAL_ROOT}.{suffix}")
