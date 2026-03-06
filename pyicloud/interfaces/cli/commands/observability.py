"""Observability CLI command group registration."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any

import asyncclick as click

ApiRequest = Callable[..., Awaitable[Any]]
LoadToken = Callable[[], str | None]
PrintJson = Callable[[Any], None]


async def _observability_query(
    *,
    ctx: click.Context,
    language: str,
    query: str,
    source: str,
    start: int | None,
    end: int | None,
    step: str,
    load_token: LoadToken,
    api_request: ApiRequest,
) -> Any:
    token = load_token()
    if token is None:
        raise click.ClickException("No local token found. Run `icloud auth login` first.")

    payload: dict[str, Any] = {"query": query}
    if source:
        payload["source"] = source

    has_range_arg = start is not None or end is not None or bool(step)
    if has_range_arg:
        if start is None or end is None or not step:
            raise click.ClickException("Range query requires --start, --end, and --step together.")
        payload["start"] = start
        payload["end"] = end
        payload["step"] = step

    return await api_request(
        api_url=ctx.obj["api_url"],
        method="POST",
        route=f"/v1/observability/{language.strip().lower()}",
        token=token,
        json_body=payload,
    )


def _extract_flow_events(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []

    explicit = payload.get("events")
    if isinstance(explicit, list):
        return [dict(item) for item in explicit if isinstance(item, dict)]

    data = payload.get("data")
    if not isinstance(data, dict):
        return []
    result = data.get("result")
    if not isinstance(result, list):
        return []

    events: list[dict[str, Any]] = []
    for stream in result:
        if not isinstance(stream, dict):
            continue
        values = stream.get("values")
        if not isinstance(values, list):
            continue
        for value in values:
            if not (isinstance(value, list) and len(value) == 2):
                continue
            ts_raw, line = value
            event: dict[str, Any] = {}
            try:
                event["timestamp_ns"] = int(str(ts_raw))
            except ValueError:
                event["timestamp_ns"] = 0
            if isinstance(line, str):
                try:
                    maybe = json.loads(line)
                except json.JSONDecodeError:
                    maybe = None
                if isinstance(maybe, dict):
                    event.update(maybe)
                else:
                    event["line"] = line
            events.append(event)
    return sorted(events, key=lambda item: int(item.get("timestamp_ns", 0)))


def _print_flow_table(*, flow_id: str, events: list[dict[str, Any]]) -> None:
    if not events:
        click.echo(f"No events found for flow_id={flow_id}")
        return

    headers = ("timestamp", "step", "method", "path", "status", "outcome", "duration_ms", "target_service")
    rows: list[tuple[str, ...]] = []
    for event in events:
        rows.append(
            (
                str(event.get("timestamp", event.get("timestamp_ns", ""))),
                str(event.get("pyicloud.step", event.get("step", ""))),
                str(event.get("method", "")),
                str(event.get("path", "")),
                str(event.get("status_code", "")),
                str(event.get("outcome", "")),
                str(event.get("duration_ms", "")),
                str(event.get("target_service", "")),
            )
        )

    widths = [len(header) for header in headers]
    for row in rows:
        widths = [max(width, len(cell)) for width, cell in zip(widths, row, strict=False)]

    def _fmt_row(cells: tuple[str, ...]) -> str:
        return " | ".join(cell.ljust(widths[idx]) for idx, cell in enumerate(cells))

    click.echo(_fmt_row(headers))
    click.echo("-+-".join("-" * width for width in widths))
    for row in rows:
        click.echo(_fmt_row(row))


def _flow_logql_query(flow_id: str) -> str:
    needle = f'"pyicloud.flow_id":"{flow_id}"'
    return f'{{component="pyicloud.upstream"}} |= "{needle}"'


def register_observability_commands(
    main_group: click.Group,
    *,
    load_token: LoadToken,
    api_request: ApiRequest,
    print_json: PrintJson,
) -> None:
    """Register the `observability` command group under the main CLI."""

    @main_group.group()
    async def observability() -> None:
        """Observability query commands."""

    @observability.command("promql")
    @click.option("--query", required=True)
    @click.option("--source", default="", show_default=False)
    @click.option("--start", type=int, default=None, show_default=False)
    @click.option("--end", type=int, default=None, show_default=False)
    @click.option("--step", default="", show_default=False)
    @click.pass_context
    async def observability_promql(
        ctx: click.Context,
        query: str,
        source: str,
        start: int | None,
        end: int | None,
        step: str,
    ) -> None:
        data = await _observability_query(
            ctx=ctx,
            language="promql",
            query=query,
            source=source,
            start=start,
            end=end,
            step=step,
            load_token=load_token,
            api_request=api_request,
        )
        print_json(data)

    @observability.command("traceql")
    @click.option("--query", required=True)
    @click.option("--source", default="", show_default=False)
    @click.option("--start", type=int, default=None, show_default=False)
    @click.option("--end", type=int, default=None, show_default=False)
    @click.option("--step", default="", show_default=False)
    @click.pass_context
    async def observability_traceql(
        ctx: click.Context,
        query: str,
        source: str,
        start: int | None,
        end: int | None,
        step: str,
    ) -> None:
        data = await _observability_query(
            ctx=ctx,
            language="traceql",
            query=query,
            source=source,
            start=start,
            end=end,
            step=step,
            load_token=load_token,
            api_request=api_request,
        )
        print_json(data)

    @observability.command("logql")
    @click.option("--query", required=True)
    @click.option("--source", default="", show_default=False)
    @click.option("--start", type=int, default=None, show_default=False)
    @click.option("--end", type=int, default=None, show_default=False)
    @click.option("--step", default="", show_default=False)
    @click.pass_context
    async def observability_logql(
        ctx: click.Context,
        query: str,
        source: str,
        start: int | None,
        end: int | None,
        step: str,
    ) -> None:
        data = await _observability_query(
            ctx=ctx,
            language="logql",
            query=query,
            source=source,
            start=start,
            end=end,
            step=step,
            load_token=load_token,
            api_request=api_request,
        )
        print_json(data)

    @observability.command("flow")
    @click.option("--flow-id", required=True)
    @click.option("--format", "output_format", type=click.Choice(["table", "json"]), default="table", show_default=True)
    @click.option("--source", default="", show_default=False)
    @click.option("--start", type=int, default=None, show_default=False)
    @click.option("--end", type=int, default=None, show_default=False)
    @click.option("--step", default="", show_default=False)
    @click.pass_context
    async def observability_flow(
        ctx: click.Context,
        flow_id: str,
        output_format: str,
        source: str,
        start: int | None,
        end: int | None,
        step: str,
    ) -> None:
        data = await _observability_query(
            ctx=ctx,
            language="logql",
            query=_flow_logql_query(flow_id),
            source=source,
            start=start,
            end=end,
            step=step,
            load_token=load_token,
            api_request=api_request,
        )
        events = _extract_flow_events(data)
        if output_format == "json":
            print_json({"flow_id": flow_id, "events": events})
            return
        _print_flow_table(flow_id=flow_id, events=events)
