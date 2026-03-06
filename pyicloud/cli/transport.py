"""Shared HTTP transport and challenge middleware for CLI command groups."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import asyncclick as click
import httpx

SendRequest = Callable[..., Awaitable[httpx.Response]]
LoadToken = Callable[[], str | None]
SaveToken = Callable[[str], None]
LoadPassword = Callable[[str], str | None]
SavePassword = Callable[[str, str], None]
ParseErrorPayload = Callable[[httpx.Response], tuple[str, dict[str, Any] | None]]
ExtractChallengeDetails = Callable[[httpx.Response], dict[str, Any] | None]
RequestJsonData = Callable[..., Awaitable[Any]]
CompleteAuthChallenge = Callable[[dict[str, Any]], Awaitable[None]]


async def send_request(
    *,
    api_url: str,
    method: str,
    route: str,
    token: str | None = None,
    json_body: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
    files: dict[str, Any] | None = None,
) -> httpx.Response:
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    async with httpx.AsyncClient(base_url=api_url, timeout=30.0) as client:
        return await client.request(
            method,
            route,
            headers=headers,
            json=json_body,
            params=params,
            files=files,
        )


def error_payload(response: httpx.Response) -> tuple[str, dict[str, Any] | None]:
    detail = response.text
    parsed_error: dict[str, Any] | None = None
    try:
        payload = response.json()
        if isinstance(payload, dict) and isinstance(payload.get("error"), dict):
            parsed_error = dict(payload["error"])
            detail = str(parsed_error.get("message", payload))
        else:
            detail = str(payload.get("detail", payload))
    except Exception:  # noqa: BLE001
        pass
    return detail, parsed_error


def auth_challenge_details(response: httpx.Response) -> dict[str, Any] | None:
    _, parsed_error = error_payload(response)
    if not isinstance(parsed_error, dict):
        return None
    if str(parsed_error.get("code")) != "auth_challenge_required":
        return None
    details = parsed_error.get("details")
    if isinstance(details, dict):
        return dict(details)
    return None


async def request_json_data(
    *,
    api_url: str,
    method: str,
    route: str,
    token: str | None = None,
    json_body: dict[str, Any] | None = None,
    send_request_fn: SendRequest = send_request,
    parse_error_payload: ParseErrorPayload = error_payload,
) -> Any:
    response = await send_request_fn(
        api_url=api_url,
        method=method,
        route=route,
        token=token,
        json_body=json_body,
    )
    if response.status_code >= 400:
        detail, _ = parse_error_payload(response)
        raise click.ClickException(f"{response.status_code}: {detail}")
    payload = response.json()
    if isinstance(payload, dict) and "data" in payload:
        return payload["data"]
    return payload


async def complete_auth_challenge(
    *,
    api_url: str,
    challenge: dict[str, Any],
    request_json_data_fn: RequestJsonData,
    save_token_fn: SaveToken,
    load_password_fn: LoadPassword | None = None,
    save_password_fn: SavePassword | None = None,
) -> None:
    username = str(challenge.get("account_id", "")).strip()
    flow_id = str(challenge.get("flow_id", "")).strip() or None
    if not username:
        username = click.prompt("Apple ID", type=str).strip()
    password = load_password_fn(username) if load_password_fn is not None else None
    if not password:
        password = click.prompt(f"Password for {username}", hide_input=True, type=str)
    login_payload: dict[str, Any] = {"username": username, "password": password}
    if flow_id:
        login_payload["flow_id"] = flow_id

    auth_result = await request_json_data_fn(
        api_url=api_url,
        method="POST",
        route="/v1/auth/login",
        json_body=login_payload,
    )
    if isinstance(auth_result, dict) and auth_result.get("status") == "challenge_required":
        challenge_id = str(auth_result.get("challenge_id", "")).strip()
        if not challenge_id:
            raise click.ClickException("Auth challenge response is missing challenge_id")
        code = click.prompt("Security code", type=str).strip()
        auth_result = await request_json_data_fn(
            api_url=api_url,
            method="POST",
            route="/v1/auth/security-code",
            json_body={
                "challenge_id": challenge_id,
                "code": code,
                "password": password,
                "username": username,
            },
        )

    if not isinstance(auth_result, dict) or auth_result.get("status") != "authenticated":
        raise click.ClickException("Authentication challenge was not completed successfully")
    token = auth_result.get("access_token")
    if token:
        save_token_fn(str(token))
    if save_password_fn is not None and username and password:
        save_password_fn(username, password)


async def api_request(
    *,
    api_url: str,
    method: str,
    route: str,
    token: str | None = None,
    json_body: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
    files: dict[str, Any] | None = None,
    allow_challenge_retry: bool = True,
    send_request_fn: SendRequest,
    parse_error_payload: ParseErrorPayload,
    extract_challenge_details: ExtractChallengeDetails,
    complete_auth_challenge_fn: CompleteAuthChallenge,
    load_token_fn: LoadToken,
) -> Any:
    response = await send_request_fn(
        api_url=api_url,
        method=method,
        route=route,
        token=token,
        json_body=json_body,
        params=params,
        files=files,
    )

    upper_method = method.strip().upper()
    if response.status_code >= 400:
        challenge = extract_challenge_details(response)
        if (
            allow_challenge_retry
            and challenge is not None
            and not route.startswith("/v1/auth/")
            and upper_method not in {"HEAD", "OPTIONS"}
        ):
            await complete_auth_challenge_fn(challenge)
            refreshed_token = load_token_fn()
            if not refreshed_token:
                raise click.ClickException("Auth challenge completed but no local token was stored.")
            if upper_method != "GET":
                should_retry = click.confirm(
                    "Authentication challenge completed. Retry previous mutating operation?",
                    default=False,
                )
                if not should_retry:
                    raise click.ClickException("Operation was not retried.")
            response = await send_request_fn(
                api_url=api_url,
                method=method,
                route=route,
                token=refreshed_token,
                json_body=json_body,
                params=params,
                files=files,
            )
            if response.status_code < 400:
                if response.headers.get("content-type", "").startswith("application/json"):
                    payload = response.json()
                    if isinstance(payload, dict) and "data" in payload:
                        return payload["data"]
                    return payload
                return response.content

        detail, _ = parse_error_payload(response)
        raise click.ClickException(f"{response.status_code}: {detail}")

    if response.headers.get("content-type", "").startswith("application/json"):
        payload = response.json()
        if isinstance(payload, dict) and "data" in payload:
            return payload["data"]
        return payload
    return response.content
