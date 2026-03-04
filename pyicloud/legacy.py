"""Compatibility stubs for removed pyicloud.base symbols."""

from __future__ import annotations


class _LegacyBaseRemovedError(RuntimeError):
    def __init__(self):
        super().__init__("pyicloud.base was removed. Use bootstrap auth/session services and endpoint adapters.")


class PyiCloudSession:
    """Removed compatibility symbol for legacy session class."""

    def __init__(self, *args, **kwargs):  # noqa: ARG002
        raise _LegacyBaseRemovedError()


class PyiCloudUser:
    """Removed compatibility symbol for legacy user class."""

    def __init__(self, *args, **kwargs):  # noqa: ARG002
        raise _LegacyBaseRemovedError()


class PyiCloud(PyiCloudUser):
    """Removed compatibility symbol for legacy PyiCloud class."""

    def __init__(self, *args, **kwargs):  # noqa: ARG002
        raise _LegacyBaseRemovedError()


__all__ = ["PyiCloud", "PyiCloudSession", "PyiCloudUser"]
