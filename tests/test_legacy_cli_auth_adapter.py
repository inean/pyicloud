from __future__ import annotations

from types import SimpleNamespace

import pytest

from pyicloud.adapters.auth import legacy_cli_auth


@pytest.mark.asyncio
async def test_authenticate_legacy_endpoint_returns_restored_endpoint():
    endpoint = object()
    auth_runner_called = []

    async def fake_auth_runner(*, username, password, interactive):  # noqa: ARG001
        auth_runner_called.append((username, password, interactive))

    restore = SimpleNamespace(restore=lambda **_: endpoint)
    restore_builder = lambda: restore

    restored = await legacy_cli_auth.authenticate_legacy_endpoint(
        username="user@example.com",
        password="secret",
        interactive=False,
        auth_runner=fake_auth_runner,
        restore_builder=restore_builder,
    )

    assert restored is endpoint
    assert auth_runner_called == [("user@example.com", "secret", False)]


@pytest.mark.asyncio
async def test_authenticate_legacy_endpoint_raises_when_restore_missing():
    async def fake_auth_runner(*, username, password, interactive):  # noqa: ARG001
        return None

    restore = SimpleNamespace(restore=lambda **_: None)
    restore_builder = lambda: restore

    with pytest.raises(RuntimeError, match="no endpoint payload found"):
        await legacy_cli_auth.authenticate_legacy_endpoint(
            username="user@example.com",
            password="secret",
            interactive=False,
            auth_runner=fake_auth_runner,
            restore_builder=restore_builder,
        )
