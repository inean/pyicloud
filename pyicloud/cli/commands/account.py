"""Account CLI command group registration."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import asyncclick as click

ApiRequest = Callable[..., Awaitable[Any]]
LoadToken = Callable[[], str | None]
PrintJson = Callable[[Any], None]


def register_account_commands(
    main_group: click.Group,
    *,
    load_token: LoadToken,
    api_request: ApiRequest,
    print_json: PrintJson,
) -> None:
    """Register the `account` command group under the main CLI."""

    @main_group.group()
    async def account() -> None:
        """Account commands."""

    @account.command("devices")
    @click.pass_context
    async def account_devices(ctx: click.Context) -> None:
        token = load_token()
        if token is None:
            raise click.ClickException("No local token found. Run `icloud auth login` first.")
        data = await api_request(api_url=ctx.obj["api_url"], method="GET", route="/v1/account/devices", token=token)
        print_json(data)

    @account.command("family")
    @click.pass_context
    async def account_family(ctx: click.Context) -> None:
        token = load_token()
        if token is None:
            raise click.ClickException("No local token found. Run `icloud auth login` first.")
        data = await api_request(api_url=ctx.obj["api_url"], method="GET", route="/v1/account/family", token=token)
        print_json(data)

    @account.command("storage")
    @click.pass_context
    async def account_storage(ctx: click.Context) -> None:
        token = load_token()
        if token is None:
            raise click.ClickException("No local token found. Run `icloud auth login` first.")
        data = await api_request(api_url=ctx.obj["api_url"], method="GET", route="/v1/account/storage", token=token)
        print_json(data)
