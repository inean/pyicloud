from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from dependency_injector import providers

import pyicloud.interfaces.cli.main as cli_main
from pyicloud.platform.composition.cli import CliRuntime, build_default_cli_container


class FakeCliRuntime:
    def __init__(self):
        self.saved_passwords: list[tuple[str, str]] = []

    def load_password(self, username: str) -> str | None:
        return f"pw:{username}"

    def save_password(self, username: str, password: str) -> None:
        self.saved_passwords.append((username, password))

    @staticmethod
    def print_json(payload: Any) -> None:  # noqa: ARG004
        return None


async def _fake_api_request(**kwargs: Any) -> Any:
    return kwargs


def test_cli_runtime_token_persistence(tmp_path: Path) -> None:
    runtime = CliRuntime(token_file=tmp_path / "token.json", credential_vault=None)
    assert runtime.load_token() is None
    runtime.save_token("abc")
    assert runtime.load_token() == "abc"
    runtime.clear_token()
    assert runtime.load_token() is None


def test_cli_container_runtime_provider_is_factory_and_overridable() -> None:
    container = build_default_cli_container()
    assert container.runtime() is not container.runtime()
    fake_runtime = FakeCliRuntime()
    with container.runtime.override(providers.Object(fake_runtime)):
        assert container.runtime() is fake_runtime


@pytest.mark.asyncio
async def test_cli_entrypoint_helpers_use_container_providers(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    container = build_default_cli_container()
    fake_runtime = FakeCliRuntime()
    token_file = tmp_path / "token.json"

    with container.runtime.override(providers.Object(fake_runtime)):
        with container.token_file.override(providers.Object(token_file)):
            with container.api_request.override(providers.Object(_fake_api_request)):
                monkeypatch.setattr(cli_main, "_CLI_CONTAINER", container)
                cli_main._save_token("stored")
                assert cli_main._load_token() == "stored"
                assert cli_main._load_password("user@example.com") == "pw:user@example.com"
                result = await cli_main._api_request(
                    api_url="http://127.0.0.1:8000",
                    method="GET",
                    route="/v1/devices",
                )

    assert result["route"] == "/v1/devices"
    assert result["method"] == "GET"
