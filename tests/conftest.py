import socket
from unittest.mock import Mock

import pytest


@pytest.fixture
def mock() -> Mock:
    return Mock()


@pytest.fixture(autouse=True)
def block_external_network(monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest):
    """Prevent accidental outbound network access in all tests unless explicitly allowed."""
    if request.node.get_closest_marker("allow_network"):
        return

    original = socket.create_connection

    def _blocked_create_connection(*args, **kwargs):  # noqa: ANN002, ANN003
        raise RuntimeError("External network access is disabled in test suite")

    monkeypatch.setattr(socket, "create_connection", _blocked_create_connection)
    return original
