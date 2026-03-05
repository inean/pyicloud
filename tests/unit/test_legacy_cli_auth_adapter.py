from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pyicloud.adapters.auth import session_endpoint_restore


@pytest.mark.asyncio
async def test_authenticate_legacy_endpoint_returns_restored_endpoint():
    endpoint = object()
    auth_runner_called = []

    async def fake_auth_runner(*, username, password, interactive):  # noqa: ARG001
        auth_runner_called.append((username, password, interactive))

    restore = SimpleNamespace(restore=lambda **_: endpoint)

    def restore_builder():
        return restore

    restored = await session_endpoint_restore.authenticate_legacy_endpoint(
        username="user@example.com",
        password="secret",
        interactive=False,
        auth_runner=fake_auth_runner,
        restore_builder=restore_builder,
    )

    assert restored is endpoint
    assert auth_runner_called == [("user@example.com", "secret", False)]


@pytest.mark.asyncio
async def test_authenticate_legacy_endpoint_loads_from_store_when_builder_not_provided():
    endpoint = object()
    auth_runner_called = []
    factory_calls: list[tuple[str, str, dict[str, Any]]] = []

    async def fake_auth_runner(*, username, password, interactive):  # noqa: ARG001
        auth_runner_called.append((username, password, interactive))

    store = SimpleNamespace(load=lambda account_id: {"webservices": {"findme": {"url": "https://example.test"}}})

    class FakeFactory:
        def from_payload(self, *, username: str, password: str, payload: dict[str, Any]) -> object:
            factory_calls.append((username, password, payload))
            return endpoint

    restored = await session_endpoint_restore.authenticate_legacy_endpoint(
        username="user@example.com",
        password="secret",
        interactive=False,
        auth_runner=fake_auth_runner,
        store=store,
        endpoint_factory=FakeFactory(),
    )

    assert restored is endpoint
    assert auth_runner_called == [("user@example.com", "secret", False)]
    assert factory_calls == [
        (
            "user@example.com",
            "secret",
            {"webservices": {"findme": {"url": "https://example.test"}}},
        )
    ]


@pytest.mark.asyncio
async def test_authenticate_legacy_endpoint_raises_when_restore_missing():
    async def fake_auth_runner(*, username, password, interactive):  # noqa: ARG001
        return None

    restore = SimpleNamespace(restore=lambda **_: None)

    def restore_builder():
        return restore

    with pytest.raises(RuntimeError, match="no endpoint payload found"):
        await session_endpoint_restore.authenticate_legacy_endpoint(
            username="user@example.com",
            password="secret",
            interactive=False,
            auth_runner=fake_auth_runner,
            restore_builder=restore_builder,
        )
