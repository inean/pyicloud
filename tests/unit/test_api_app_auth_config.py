from __future__ import annotations

import pytest

from pyicloud.adapters.session import FileApiSessionStore, InMemoryApiSessionStore
from pyicloud.api.app import _build_default_auth_service


def _clear_auth_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PYICLOUD_API_ENV", raising=False)
    monkeypatch.delenv("PYICLOUD_ENV", raising=False)
    monkeypatch.delenv("PYICLOUD_API_JWT_SECRET", raising=False)
    monkeypatch.delenv("PYICLOUD_API_JWT_LEEWAY_SECONDS", raising=False)
    monkeypatch.delenv("PYICLOUD_API_SESSION_BACKEND", raising=False)
    monkeypatch.delenv("PYICLOUD_API_SESSION_STORE_DIR", raising=False)


def test_non_dev_runtime_requires_explicit_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_auth_env(monkeypatch)
    monkeypatch.setenv("PYICLOUD_API_ENV", "production")

    with pytest.raises(RuntimeError, match="must be explicitly configured"):
        _build_default_auth_service()


def test_non_dev_runtime_rejects_weak_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_auth_env(monkeypatch)
    monkeypatch.setenv("PYICLOUD_API_ENV", "production")
    monkeypatch.setenv("PYICLOUD_API_JWT_SECRET", "short")

    with pytest.raises(RuntimeError, match="too weak"):
        _build_default_auth_service()


def test_build_default_auth_service_supports_file_session_backend(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    _clear_auth_env(monkeypatch)
    monkeypatch.setenv("PYICLOUD_API_ENV", "dev")
    monkeypatch.setenv("PYICLOUD_API_SESSION_BACKEND", "file")
    monkeypatch.setenv("PYICLOUD_API_SESSION_STORE_DIR", str(tmp_path))

    service = _build_default_auth_service()

    assert isinstance(service._session_query, FileApiSessionStore)
    assert isinstance(service._session_command, FileApiSessionStore)


def test_build_default_auth_service_uses_memory_backend_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_auth_env(monkeypatch)
    monkeypatch.setenv("PYICLOUD_API_ENV", "dev")

    service = _build_default_auth_service()

    assert isinstance(service._session_query, InMemoryApiSessionStore)
    assert isinstance(service._session_command, InMemoryApiSessionStore)


def test_build_default_auth_service_rejects_invalid_jwt_leeway(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_auth_env(monkeypatch)
    monkeypatch.setenv("PYICLOUD_API_ENV", "dev")
    monkeypatch.setenv("PYICLOUD_API_JWT_LEEWAY_SECONDS", "invalid")

    with pytest.raises(RuntimeError, match="must be an integer"):
        _build_default_auth_service()
