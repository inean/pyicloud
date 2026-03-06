"""API-first CLI composition root."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import asyncclick as click
import httpx

from . import credential_vault, token_store, transport
from .commands import (
    register_account_commands,
    register_auth_commands,
    register_calendar_commands,
    register_contacts_commands,
    register_devices_commands,
    register_drive_commands,
    register_observability_commands,
    register_photos_commands,
    register_reminders_commands,
    register_ubiquity_commands,
)

DEFAULT_API_URL = "http://127.0.0.1:8000"
TOKEN_FILE_ENV = token_store.TOKEN_FILE_ENV
_CREDENTIAL_VAULT = credential_vault.build_default_vault()


def _token_file() -> Path:
    return token_store.token_file()


def _load_token() -> str | None:
    return token_store.load_token(path=_token_file())


def _save_token(token: str) -> None:
    token_store.save_token(token, path=_token_file())


def _clear_token() -> None:
    token_store.clear_token(path=_token_file())


def _load_password(username: str) -> str | None:
    if _CREDENTIAL_VAULT is None:
        return None
    try:
        return _CREDENTIAL_VAULT.load(username=username)
    except Exception:  # noqa: BLE001
        return None


def _save_password(username: str, password: str) -> None:
    if _CREDENTIAL_VAULT is None:
        return None
    try:
        _CREDENTIAL_VAULT.save(username=username, password=password)
    except Exception:  # noqa: BLE001
        return None


def _clear_password(username: str) -> None:
    if _CREDENTIAL_VAULT is None:
        return None
    try:
        _CREDENTIAL_VAULT.clear(username=username)
    except Exception:  # noqa: BLE001
        return None


async def _send_request(
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
    return await transport.send_request(
        api_url=api_url,
        method=method,
        route=route,
        token=token,
        json_body=json_body,
        params=params,
        files=files,
        idempotency_key=idempotency_key,
    )


def _error_payload(response: httpx.Response) -> tuple[str, dict[str, Any] | None]:
    return transport.error_payload(response)


def _auth_challenge_details(response: httpx.Response) -> dict[str, Any] | None:
    return transport.auth_challenge_details(response)


async def _request_json_data(
    *,
    api_url: str,
    method: str,
    route: str,
    token: str | None = None,
    json_body: dict[str, Any] | None = None,
) -> Any:
    return await transport.request_json_data(
        api_url=api_url,
        method=method,
        route=route,
        token=token,
        json_body=json_body,
        send_request_fn=_send_request,
        parse_error_payload=_error_payload,
    )


async def _complete_auth_challenge(*, api_url: str, challenge: dict[str, Any]) -> dict[str, Any]:
    return await transport.complete_auth_challenge(
        api_url=api_url,
        challenge=challenge,
        request_json_data_fn=_request_json_data,
        save_token_fn=_save_token,
        load_password_fn=_load_password,
        save_password_fn=_save_password,
    )


async def _api_request(
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
        return await _complete_auth_challenge(api_url=api_url, challenge=challenge)

    return await transport.api_request(
        api_url=api_url,
        method=method,
        route=route,
        token=token,
        json_body=json_body,
        params=params,
        files=files,
        allow_challenge_retry=allow_challenge_retry,
        send_request_fn=_send_request,
        parse_error_payload=_error_payload,
        extract_challenge_details=_auth_challenge_details,
        complete_auth_challenge_fn=_handle_challenge,
        load_token_fn=_load_token,
    )


def _print_json(payload: Any) -> None:
    click.echo(json.dumps(payload, indent=2, sort_keys=True, default=str))


@click.group(help="pyicloud API-driven CLI")
@click.option("--api-url", default=lambda: os.getenv("PYICLOUD_API_URL", DEFAULT_API_URL), show_default=True)
@click.pass_context
async def main(ctx: click.Context, api_url: str) -> None:
    ctx.ensure_object(dict)
    ctx.obj["api_url"] = api_url.rstrip("/")


register_auth_commands(
    main,
    load_token=lambda: _load_token(),
    save_token=lambda token: _save_token(token),
    clear_token=lambda: _clear_token(),
    load_password=lambda username: _load_password(username),
    save_password=lambda username, password: _save_password(username, password),
    api_request=lambda **kwargs: _api_request(**kwargs),
    print_json=lambda payload: _print_json(payload),
)
register_devices_commands(
    main,
    load_token=lambda: _load_token(),
    api_request=lambda **kwargs: _api_request(**kwargs),
    print_json=lambda payload: _print_json(payload),
)
register_account_commands(
    main,
    load_token=lambda: _load_token(),
    api_request=lambda **kwargs: _api_request(**kwargs),
    print_json=lambda payload: _print_json(payload),
)
register_drive_commands(
    main,
    load_token=lambda: _load_token(),
    api_request=lambda **kwargs: _api_request(**kwargs),
    print_json=lambda payload: _print_json(payload),
)
register_calendar_commands(
    main,
    load_token=lambda: _load_token(),
    api_request=lambda **kwargs: _api_request(**kwargs),
    print_json=lambda payload: _print_json(payload),
)
register_contacts_commands(
    main,
    load_token=lambda: _load_token(),
    api_request=lambda **kwargs: _api_request(**kwargs),
    print_json=lambda payload: _print_json(payload),
)
register_reminders_commands(
    main,
    load_token=lambda: _load_token(),
    api_request=lambda **kwargs: _api_request(**kwargs),
    print_json=lambda payload: _print_json(payload),
)
register_photos_commands(
    main,
    load_token=lambda: _load_token(),
    api_request=lambda **kwargs: _api_request(**kwargs),
    print_json=lambda payload: _print_json(payload),
)
register_ubiquity_commands(
    main,
    load_token=lambda: _load_token(),
    api_request=lambda **kwargs: _api_request(**kwargs),
    print_json=lambda payload: _print_json(payload),
)
register_observability_commands(
    main,
    load_token=lambda: _load_token(),
    api_request=lambda **kwargs: _api_request(**kwargs),
    print_json=lambda payload: _print_json(payload),
)


if __name__ == "__main__":
    main()
