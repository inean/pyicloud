"""Compatibility shim for file session store moved to platform."""

from pyicloud.platform.storage.session_store import FileSessionStoreAdapter

__all__ = ["FileSessionStoreAdapter"]
