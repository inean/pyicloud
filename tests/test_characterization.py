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


def test_cmdline_lostmode_options_map_to_expected_fields():
    option_names = {
        option.name
        for option in cmdline.main.params
        if getattr(option, "name", None) is not None
    }
    assert "lost_phone" in option_names
    assert "lost_message" in option_names
    assert "lost_password" in option_names
