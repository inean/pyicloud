"""Reminders CLI command group registration."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import asyncclick as click

ApiRequest = Callable[..., Awaitable[Any]]
LoadToken = Callable[[], str | None]
PrintJson = Callable[[Any], None]


def register_reminders_commands(
    main_group: click.Group,
    *,
    load_token: LoadToken,
    api_request: ApiRequest,
    print_json: PrintJson,
) -> None:
    """Register the `reminders` command group under the main CLI."""

    @main_group.group()
    async def reminders() -> None:
        """Reminders commands."""

    @reminders.command("list")
    @click.pass_context
    async def reminders_list(ctx: click.Context) -> None:
        token = load_token()
        if token is None:
            raise click.ClickException("No local token found. Run `icloud auth login` first.")
        data = await api_request(api_url=ctx.obj["api_url"], method="GET", route="/v1/reminders", token=token)
        print_json(data)

    @reminders.command("add")
    @click.option("--title", required=True)
    @click.option("--description", default="", show_default=True)
    @click.option("--collection", default="", show_default=False)
    @click.option("--due-date", default="", help="ISO datetime due value.")
    @click.pass_context
    async def reminders_add(
        ctx: click.Context,
        title: str,
        description: str,
        collection: str,
        due_date: str,
    ) -> None:
        token = load_token()
        if token is None:
            raise click.ClickException("No local token found. Run `icloud auth login` first.")
        payload: dict[str, Any] = {"title": title, "description": description}
        if collection:
            payload["collection"] = collection
        if due_date:
            payload["due_date"] = due_date
        data = await api_request(
            api_url=ctx.obj["api_url"],
            method="POST",
            route="/v1/reminders",
            token=token,
            json_body=payload,
        )
        print_json(data)
