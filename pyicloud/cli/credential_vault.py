"""Optional OS keyring-backed credential vault for CLI Apple passwords."""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any, Protocol

KEYRING_ENABLED_ENV = "PYICLOUD_CLI_KEYRING_ENABLED"
KEYRING_SERVICE_ENV = "PYICLOUD_CLI_KEYRING_SERVICE"
DEFAULT_KEYRING_SERVICE = "pyicloud"


class CredentialVault(Protocol):
    """Contract for secure CLI credential storage."""

    def load(self, *, username: str) -> str | None: ...

    def save(self, *, username: str, password: str) -> None: ...

    def clear(self, *, username: str) -> None: ...


class KeyringCredentialVault:
    """Credential vault implementation backed by the local OS keyring."""

    def __init__(self, *, keyring_module: Any, service_name: str):
        self._keyring = keyring_module
        self._service_name = service_name

    def load(self, *, username: str) -> str | None:
        value = self._keyring.get_password(self._service_name, username)
        return str(value) if value else None

    def save(self, *, username: str, password: str) -> None:
        self._keyring.set_password(self._service_name, username, password)

    def clear(self, *, username: str) -> None:
        try:
            self._keyring.delete_password(self._service_name, username)
        except Exception:  # noqa: BLE001
            # Keyring backends raise if an entry does not exist.
            return None


def keyring_enabled(*, getenv: Callable[[str, str], str] = os.getenv) -> bool:
    raw = getenv(KEYRING_ENABLED_ENV, "1").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def build_default_vault(*, keyring_module: Any | None = None) -> CredentialVault | None:
    """
    Build the default credential vault.

    The CLI only uses OS keyring storage. No plaintext or encrypted-file fallback
    is enabled by default.
    """
    if not keyring_enabled():
        return None

    module = keyring_module
    if module is None:
        try:
            import keyring as imported_keyring
        except Exception:  # noqa: BLE001
            return None
        module = imported_keyring

    service_name = os.getenv(KEYRING_SERVICE_ENV, DEFAULT_KEYRING_SERVICE).strip() or DEFAULT_KEYRING_SERVICE
    return KeyringCredentialVault(keyring_module=module, service_name=service_name)
