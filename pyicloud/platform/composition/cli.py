"""CLI composition root based on dependency-injector providers."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import asyncclick as click
import httpx
from dependency_injector import containers, providers

from pyicloud.interfaces.cli import credential_vault as credential_vault_module
from pyicloud.interfaces.cli import token_store, transport


class CliRuntime:
    """Runtime facade used by CLI entrypoint wrappers."""

    def __init__(
        self,
        *,
        token_file: Path,
        credential_vault: credential_vault_module.CredentialVault | None,
        send_request_fn: transport.SendRequest = transport.send_request,
        parse_error_payload_fn: transport.ParseErrorPayload = transport.error_payload,
        extract_challenge_details_fn: transport.ExtractChallengeDetails = transport.auth_challenge_details,
        request_json_data_fn: transport.RequestJsonData = transport.request_json_data,
        complete_auth_challenge_fn: transport.CompleteAuthChallenge = transport.complete_auth_challenge,
        api_request_fn: Callable[..., Awaitable[Any]] = transport.api_request,
    ):
        self._token_file = token_file
        self._credential_vault = credential_vault
        self._send_request_fn = send_request_fn
        self._parse_error_payload_fn = parse_error_payload_fn
        self._extract_challenge_details_fn = extract_challenge_details_fn
        self._request_json_data_fn = request_json_data_fn
        self._complete_auth_challenge_fn = complete_auth_challenge_fn
        self._api_request_fn = api_request_fn

    def load_token(self) -> str | None:
        return token_store.load_token(path=self._token_file)

    def save_token(self, token: str) -> None:
        token_store.save_token(token, path=self._token_file)

    def clear_token(self) -> None:
        token_store.clear_token(path=self._token_file)

    def load_password(self, username: str) -> str | None:
        if self._credential_vault is None:
            return None
        try:
            return self._credential_vault.load(username=username)
        except Exception:  # noqa: BLE001
            return None

    def save_password(self, username: str, password: str) -> None:
        if self._credential_vault is None:
            return None
        try:
            self._credential_vault.save(username=username, password=password)
        except Exception:  # noqa: BLE001
            return None

    def clear_password(self, username: str) -> None:
        if self._credential_vault is None:
            return None
        try:
            self._credential_vault.clear(username=username)
        except Exception:  # noqa: BLE001
            return None

    async def send_request(
        self,
        *,
        api_url: str,
        method: str,
        route: str,
        token: str | None = None,
        json_body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        files: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> httpx.Response:
        return await self._send_request_fn(
            api_url=api_url,
            method=method,
            route=route,
            token=token,
            json_body=json_body,
            params=params,
            files=files,
            idempotency_key=idempotency_key,
        )

    def error_payload(self, response: httpx.Response) -> tuple[str, dict[str, Any] | None]:
        return self._parse_error_payload_fn(response)

    def auth_challenge_details(self, response: httpx.Response) -> dict[str, Any] | None:
        return self._extract_challenge_details_fn(response)

    async def request_json_data(
        self,
        *,
        api_url: str,
        method: str,
        route: str,
        token: str | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> Any:
        return await self._request_json_data_fn(
            api_url=api_url,
            method=method,
            route=route,
            token=token,
            json_body=json_body,
            send_request_fn=self.send_request,
            parse_error_payload=self.error_payload,
        )

    async def complete_auth_challenge(self, *, api_url: str, challenge: dict[str, Any]) -> dict[str, Any]:
        return await self._complete_auth_challenge_fn(
            api_url=api_url,
            challenge=challenge,
            request_json_data_fn=self.request_json_data,
            save_token_fn=self.save_token,
            load_password_fn=self.load_password,
            save_password_fn=self.save_password,
        )

    async def api_request(
        self,
        *,
        api_url: str,
        method: str,
        route: str,
        token: str | None = None,
        json_body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        files: dict[str, Any] | None = None,
        allow_challenge_retry: bool = True,
    ) -> Any:
        async def _handle_challenge(challenge: dict[str, Any]) -> dict[str, Any]:
            return await self.complete_auth_challenge(api_url=api_url, challenge=challenge)

        return await self._api_request_fn(
            api_url=api_url,
            method=method,
            route=route,
            token=token,
            json_body=json_body,
            params=params,
            files=files,
            allow_challenge_retry=allow_challenge_retry,
            send_request_fn=self.send_request,
            parse_error_payload=self.error_payload,
            extract_challenge_details=self.auth_challenge_details,
            complete_auth_challenge_fn=_handle_challenge,
            load_token_fn=self.load_token,
        )

    @staticmethod
    def print_json(payload: Any) -> None:
        click.echo(json.dumps(payload, indent=2, sort_keys=True, default=str))


class CliContainer(containers.DeclarativeContainer):
    """Dependency-injector container for CLI entrypoint composition."""

    token_file = providers.Callable(token_store.token_file)
    credential_vault = providers.Singleton(credential_vault_module.build_default_vault)
    send_request = providers.Object(transport.send_request)
    error_payload = providers.Object(transport.error_payload)
    auth_challenge_details = providers.Object(transport.auth_challenge_details)
    request_json_data = providers.Object(transport.request_json_data)
    complete_auth_challenge = providers.Object(transport.complete_auth_challenge)
    api_request = providers.Object(transport.api_request)
    runtime = providers.Factory(
        CliRuntime,
        token_file=token_file,
        credential_vault=credential_vault,
        send_request_fn=send_request,
        parse_error_payload_fn=error_payload,
        extract_challenge_details_fn=auth_challenge_details,
        request_json_data_fn=request_json_data,
        complete_auth_challenge_fn=complete_auth_challenge,
        api_request_fn=api_request,
    )


def build_default_cli_container() -> CliContainer:
    """Build the default CLI DI container."""
    return CliContainer()


__all__ = ["CliContainer", "CliRuntime", "build_default_cli_container"]
