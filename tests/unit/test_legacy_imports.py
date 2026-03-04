"""Legacy compatibility import tests."""

import pytest

from pyicloud.legacy import PyiCloud, PyiCloudSession, PyiCloudUser


def test_legacy_exports_base_symbols():
    assert PyiCloud is not None
    assert PyiCloudSession is not None
    assert PyiCloudUser is not None


def test_legacy_symbols_raise_guidance_error_when_constructed():
    with pytest.raises(RuntimeError, match="pyicloud.base was removed"):
        PyiCloud("user@example.com", "secret")

    with pytest.raises(RuntimeError, match="pyicloud.base was removed"):
        PyiCloudUser({})

    with pytest.raises(RuntimeError, match="pyicloud.base was removed"):
        PyiCloudSession(object())
