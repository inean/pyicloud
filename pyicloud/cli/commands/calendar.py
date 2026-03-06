"""Calendar CLI command group registration."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import asyncclick as click

ApiRequest = Callable[..., Awaitable[Any]]
LoadToken = Callable[[], str | None]
PrintJson = Callable[[Any], None]


def register_calendar_commands(
    main_group: click.Group,
    *,
    load_token: LoadToken,
    api_request: ApiRequest,
    print_json: PrintJson,
) -> None:
    """Register the `calendar` command group under the main CLI."""

    @main_group.group()
    async def calendar() -> None:
        """Calendar commands."""

    @calendar.command("calendars")
    @click.pass_context
    async def calendar_calendars(ctx: click.Context) -> None:
        token = load_token()
        if token is None:
            raise click.ClickException("No local token found. Run `icloud auth login` first.")
        data = await api_request(api_url=ctx.obj["api_url"], method="GET", route="/v1/calendar/calendars", token=token)
        print_json(data)

    @calendar.command("events")
    @click.option("--from-dt", default="", help="ISO datetime start boundary.")
    @click.option("--to-dt", default="", help="ISO datetime end boundary.")
    @click.pass_context
    async def calendar_events(ctx: click.Context, from_dt: str, to_dt: str) -> None:
        token = load_token()
        if token is None:
            raise click.ClickException("No local token found. Run `icloud auth login` first.")
        params: dict[str, Any] = {}
        if from_dt:
            params["from_dt"] = from_dt
        if to_dt:
            params["to_dt"] = to_dt
        data = await api_request(
            api_url=ctx.obj["api_url"],
            method="GET",
            route="/v1/calendar/events",
            token=token,
            params=params or None,
        )
        print_json(data)

    @calendar.command("event-detail")
    @click.option("--calendar-guid", required=True)
    @click.option("--event-guid", required=True)
    @click.pass_context
    async def calendar_event_detail(ctx: click.Context, calendar_guid: str, event_guid: str) -> None:
        token = load_token()
        if token is None:
            raise click.ClickException("No local token found. Run `icloud auth login` first.")
        data = await api_request(
            api_url=ctx.obj["api_url"],
            method="GET",
            route="/v1/calendar/event-detail",
            token=token,
            params={"calendar_guid": calendar_guid, "event_guid": event_guid},
        )
        print_json(data)
