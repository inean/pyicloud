"""Compatibility facade for decorator helpers moved to shared kernel."""

from pyicloud.shared.kernel.decorators import (  # noqa: F401
    Deprecated,
    classproperty,
    deprecated,
)

__all__ = ["Deprecated", "classproperty", "deprecated"]
