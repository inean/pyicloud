"""Legacy compatibility import tests."""

from pyicloud.legacy import PyiCloud, PyiCloudSession, PyiCloudUser


def test_legacy_exports_base_symbols():
    assert PyiCloud is not None
    assert PyiCloudSession is not None
    assert PyiCloudUser is not None
