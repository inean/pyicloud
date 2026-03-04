from __future__ import annotations

from pyicloud import PyiCloudService
from pyicloud import cmdline
from pyicloud.services import PyiCloudServices


def test_top_level_pyicloudservice_import_is_available():
    assert PyiCloudService is not None


def test_proxy_forwards_attributes_to_authenticated_target():
    class FakeEndpoint:
        def authenticate(self, service=None):  # noqa: ARG002
            return None

        def __getitem__(self, service):  # noqa: ARG002
            return "https://service.example.test"

    class FakeTarget:
        def __init__(self, endpoint_url, **params):  # noqa: ARG002
            self.endpoint_url = endpoint_url
            self.value = "expected"

    proxy = PyiCloudServices._Proxy(FakeTarget, "findme", FakeEndpoint(), {})
    proxy.authenticate()

    assert proxy.value == "expected"


def test_cmdline_migration_guide_includes_lost_mode_mapping():
    assert "--lostmode --device <id>" in cmdline.MIGRATION_GUIDE
    assert "icloud devices lost-mode <id>" in cmdline.MIGRATION_GUIDE
