"""Auth CLI command group registration."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import asyncclick as click

ApiRequest = Callable[..., Awaitable[Any]]
LoadToken = Callable[[], str | None]
SaveToken = Callable[[str], None]
ClearToken = Callable[[], None]
PrintJson = Callable[[Any], None]


def register_auth_commands(
    main_group: click.Group,
    *,
    load_token: LoadToken,
    save_token: SaveToken,
    clear_token: ClearToken,
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
        print_json(data)

    @auth.command("security-code")
    @click.option("--challenge-id", required=True)
    @click.option("--code", required=True)
    @click.option("--password", required=True, prompt=True, hide_input=True)
    @click.pass_context
    async def auth_security_code(ctx: click.Context, challenge_id: str, code: str, password: str) -> None:
        data = await api_request(
            api_url=ctx.obj["api_url"],
            method="POST",
            route="/v1/auth/security-code",
            json_body={"challenge_id": challenge_id, "code": code, "password": password},
        )
        token = data.get("access_token") if isinstance(data, dict) else None
        if token:
            save_token(str(token))
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
