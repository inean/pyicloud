"""Auth CLI command group registration."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import asyncclick as click

ApiRequest = Callable[..., Awaitable[Any]]
LoadToken = Callable[[], str | None]
SaveToken = Callable[[str], None]
ClearToken = Callable[[], None]
LoadPassword = Callable[[str], str | None]
SavePassword = Callable[[str, str], None]
PrintJson = Callable[[Any], None]


def register_auth_commands(
    main_group: click.Group,
    *,
    load_token: LoadToken,
    save_token: SaveToken,
    clear_token: ClearToken,
    load_password: LoadPassword | None,
    save_password: SavePassword | None,
    api_request: ApiRequest,
    print_json: PrintJson,
) -> None:
    """Register the `auth` command group under the main CLI."""

    @main_group.group()
    async def auth() -> None:
        """Authentication commands."""

    @auth.command("login")
    @click.option("--username", required=True)
    @click.option("--password", required=True, prompt=True, hide_input=True)
    @click.pass_context
    async def auth_login(ctx: click.Context, username: str, password: str) -> None:
        data = await api_request(
            api_url=ctx.obj["api_url"],
            method="POST",
            route="/v1/auth/login",
            json_body={"username": username, "password": password},
        )
        token = data.get("access_token") if isinstance(data, dict) else None
        if token:
            save_token(str(token))
        if save_password is not None:
            save_password(username, password)
        print_json(data)

    @auth.command("security-code")
    @click.option("--challenge-id", required=True)
    @click.option("--code", required=True)
    @click.option("--username", required=False)
    @click.option("--password", required=False, hide_input=True)
    @click.pass_context
    async def auth_security_code(
        ctx: click.Context,
        challenge_id: str,
        code: str,
        username: str | None,
        password: str | None,
    ) -> None:
        resolved_password = password
        if not resolved_password and username and load_password is not None:
            resolved_password = load_password(username)
        if not resolved_password:
            prompt_subject = username or "Apple ID"
            resolved_password = click.prompt(f"Password for {prompt_subject}", hide_input=True, type=str)

        data = await api_request(
            api_url=ctx.obj["api_url"],
            method="POST",
            route="/v1/auth/security-code",
            json_body={
                "challenge_id": challenge_id,
                "code": code,
                "password": resolved_password,
                "username": username,
            },
        )
        token = data.get("access_token") if isinstance(data, dict) else None
        if token:
            save_token(str(token))
        if save_password is not None and username and resolved_password:
            save_password(username, resolved_password)
        print_json(data)

    @auth.command("session")
    @click.pass_context
    async def auth_session(ctx: click.Context) -> None:
        token = load_token()
        if token is None:
            raise click.ClickException("No local token found. Run `icloud auth login` first.")
        data = await api_request(api_url=ctx.obj["api_url"], method="GET", route="/v1/auth/session", token=token)
        print_json(data)

    @auth.command("logout")
    @click.pass_context
    async def auth_logout(ctx: click.Context) -> None:
        token = load_token()
        if token is None:
            raise click.ClickException("No local token found.")
        data = await api_request(api_url=ctx.obj["api_url"], method="POST", route="/v1/auth/logout", token=token)
        clear_token()
        print_json(data)
