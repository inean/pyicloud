from __future__ import annotations

import pytest

from pyicloud.adapters.auth import legacy_cli_auth
from pyicloud.exceptions import PyiCloudFailedLoginException


def test_authenticate_legacy_endpoint_returns_api_on_success(monkeypatch):
    class FakeApi:
        requires_password = False
        requires_2sa = False
        requires_2fa = False

        def __init__(self):
            self.calls = 0

        def authenticate(self):
            self.calls += 1

    api = FakeApi()
    monkeypatch.setattr(legacy_cli_auth, "PyiCloud", lambda **_: api)

    restored = legacy_cli_auth.authenticate_legacy_endpoint(
        username="user@example.com",
        password="secret",
        interactive=False,
    )

    assert restored is api
    assert api.calls == 1


def test_authenticate_legacy_endpoint_raises_runtime_error_on_failed_login(monkeypatch):
    class FakeApi:
        requires_password = False
        requires_2sa = False
        requires_2fa = False

        def authenticate(self):
            raise PyiCloudFailedLoginException("bad credentials")

    monkeypatch.setattr(legacy_cli_auth, "PyiCloud", lambda **_: FakeApi())

    with pytest.raises(RuntimeError, match="Bad username or password"):
        legacy_cli_auth.authenticate_legacy_endpoint(
            username="user@example.com",
            password="secret",
            interactive=False,
        )


def test_authenticate_legacy_endpoint_raises_value_error_on_validation(monkeypatch):
    class FakeValidationError(Exception):
        def errors(self):
            return [{"msg": "Invalid email"}]

    def raise_validation(**_):
        raise FakeValidationError()

    monkeypatch.setattr(legacy_cli_auth, "PyiCloudValidationError", FakeValidationError)
    monkeypatch.setattr(legacy_cli_auth, "PyiCloud", raise_validation)

    with pytest.raises(ValueError, match="Invalid email"):
        legacy_cli_auth.authenticate_legacy_endpoint(
            username="not-an-email",
            password="secret",
            interactive=False,
        )
