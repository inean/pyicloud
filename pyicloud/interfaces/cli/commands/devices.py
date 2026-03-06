"""Devices CLI command group registration."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import asyncclick as click

ApiRequest = Callable[..., Awaitable[Any]]
LoadToken = Callable[[], str | None]
PrintJson = Callable[[Any], None]


def register_devices_commands(
    main_group: click.Group,
    *,
    load_token: LoadToken,
    api_request: ApiRequest,
    print_json: PrintJson,
) -> None:
    """Register the `devices` command group under the main CLI."""

    @main_group.group()
    async def devices() -> None:
        """Find My iPhone device commands."""

    @devices.command("list")
    @click.pass_context
    async def devices_list(ctx: click.Context) -> None:
        token = load_token()
        if token is None:
            raise click.ClickException("No local token found. Run `icloud auth login` first.")
        data = await api_request(api_url=ctx.obj["api_url"], method="GET", route="/v1/devices", token=token)
        print_json(data)

    @devices.command("location")
    @click.argument("device_id")
    @click.pass_context
    async def devices_location(ctx: click.Context, device_id: str) -> None:
        token = load_token()
        if token is None:
            raise click.ClickException("No local token found. Run `icloud auth login` first.")
        data = await api_request(
            api_url=ctx.obj["api_url"],
            method="GET",
            route=f"/v1/devices/{device_id}/location",
            token=token,
        )
        print_json(data)

    @devices.command("status")
    @click.argument("device_id")
    @click.pass_context
    async def devices_status(ctx: click.Context, device_id: str) -> None:
        token = load_token()
        if token is None:
            raise click.ClickException("No local token found. Run `icloud auth login` first.")
        data = await api_request(
            api_url=ctx.obj["api_url"],
            method="GET",
            route=f"/v1/devices/{device_id}/status",
            token=token,
        )
        print_json(data)

    @devices.command("play-sound")
    @click.argument("device_id")
    @click.option("--subject", default="Find My iPhone Alert", show_default=True)
    @click.pass_context
    async def devices_play_sound(ctx: click.Context, device_id: str, subject: str) -> None:
        token = load_token()
        if token is None:
            raise click.ClickException("No local token found. Run `icloud auth login` first.")
        data = await api_request(
            api_url=ctx.obj["api_url"],
            method="POST",
            route=f"/v1/devices/{device_id}/actions/play-sound",
            token=token,
            json_body={"subject": subject},
        )
        print_json(data)

    @devices.command("message")
    @click.argument("device_id")
    @click.option("--subject", default="Find My iPhone Alert", show_default=True)
    @click.option("--message", required=True)
    @click.option("--sounds/--no-sounds", default=False)
    @click.pass_context
    async def devices_message(
        ctx: click.Context,
        device_id: str,
        subject: str,
        message: str,
        sounds: bool,
    ) -> None:
        token = load_token()
        if token is None:
            raise click.ClickException("No local token found. Run `icloud auth login` first.")
        data = await api_request(
            api_url=ctx.obj["api_url"],
            method="POST",
            route=f"/v1/devices/{device_id}/actions/message",
            token=token,
            json_body={"subject": subject, "message": message, "sounds": sounds},
        )
        print_json(data)

    @devices.command("lost-mode")
    @click.argument("device_id")
    @click.option("--number", required=True)
    @click.option("--text", default="This iPhone has been lost. Please call me.", show_default=True)
    @click.option("--newpasscode", default="", show_default=True)
    @click.pass_context
    async def devices_lost_mode(
        ctx: click.Context,
        device_id: str,
        number: str,
        text: str,
        newpasscode: str,
    ) -> None:
        token = load_token()
        if token is None:
            raise click.ClickException("No local token found. Run `icloud auth login` first.")
        data = await api_request(
            api_url=ctx.obj["api_url"],
            method="POST",
            route=f"/v1/devices/{device_id}/actions/lost-mode",
            token=token,
            json_body={"number": number, "text": text, "newpasscode": newpasscode},
        )
        print_json(data)
