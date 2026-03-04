from __future__ import annotations

import socket
from pathlib import Path

import pytest

from pyicloud.api import create_app
from tests.fakes.auth_scenarios import build_fake_auth_api_service, build_noop_core_services


@pytest.fixture(autouse=True)
def block_external_network(monkeypatch: pytest.MonkeyPatch):
    """Prevent accidental outbound network access in vertical tests."""

    def _blocked_create_connection(*args, **kwargs):  # noqa: ANN002, ANN003
        raise RuntimeError("External network access is disabled in vertical tests")

    monkeypatch.setattr(socket, "create_connection", _blocked_create_connection)


@pytest.fixture()
def app(tmp_path: Path):
    auth_service = build_fake_auth_api_service(tmp_path)
    core_services = build_noop_core_services()
    return create_app(auth_service=auth_service, core_services=core_services)
