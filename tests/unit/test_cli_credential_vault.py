from __future__ import annotations

import pytest

from pyicloud.cli import credential_vault


class _FakeKeyring:
    def __init__(self):
        self.store: dict[tuple[str, str], str] = {}

    def get_password(self, service_name: str, username: str) -> str | None:
        return self.store.get((service_name, username))

    def set_password(self, service_name: str, username: str, password: str) -> None:
        self.store[(service_name, username)] = password

    def delete_password(self, service_name: str, username: str) -> None:
        self.store.pop((service_name, username), None)


def test_keyring_enabled_default_true(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PYICLOUD_CLI_KEYRING_ENABLED", raising=False)
    assert credential_vault.keyring_enabled() is True


def test_build_default_vault_returns_none_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PYICLOUD_CLI_KEYRING_ENABLED", "0")
    assert credential_vault.build_default_vault(keyring_module=_FakeKeyring()) is None


def test_keyring_credential_vault_roundtrip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PYICLOUD_CLI_KEYRING_ENABLED", "1")
    monkeypatch.setenv("PYICLOUD_CLI_KEYRING_SERVICE", "pyicloud-test")
    fake_keyring = _FakeKeyring()

    vault = credential_vault.build_default_vault(keyring_module=fake_keyring)

    assert vault is not None
    assert vault.load(username="user@example.com") is None
    vault.save(username="user@example.com", password="secret")
    assert vault.load(username="user@example.com") == "secret"
    vault.clear(username="user@example.com")
    assert vault.load(username="user@example.com") is None
