"""API-first CLI with subcommands for auth and core services."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import asyncclick as click
import httpx

DEFAULT_API_URL = "http://127.0.0.1:8000"
TOKEN_FILE_ENV = "PYICLOUD_API_TOKEN_FILE"


def _token_file() -> Path:
    raw = os.getenv(TOKEN_FILE_ENV, ".cache/pyicloud/api/token.json")
    return Path(raw).expanduser()


def _load_token() -> str | None:
    path = _token_file()
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    token = payload.get("access_token")
    return str(token) if token else None


def _save_token(token: str) -> None:
    path = _token_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"access_token": token}, separators=(",", ":")), encoding="utf-8")


def _clear_token() -> None:
    path = _token_file()
    if path.exists():
        path.unlink()


async def _send_request(
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


def _error_payload(response: httpx.Response) -> tuple[str, dict[str, Any] | None]:
    detail = response.text
    error_payload: dict[str, Any] | None = None
    try:
        payload = response.json()
        if isinstance(payload, dict) and isinstance(payload.get("error"), dict):
            error_payload = dict(payload["error"])
            detail = str(error_payload.get("message", payload))
        else:
            detail = str(payload.get("detail", payload))
    except Exception:  # noqa: BLE001
        pass
    return detail, error_payload


def _auth_challenge_details(response: httpx.Response) -> dict[str, Any] | None:
    _, error_payload = _error_payload(response)
    if not isinstance(error_payload, dict):
        return None
    if str(error_payload.get("code")) != "auth_challenge_required":
        return None
    details = error_payload.get("details")
    if isinstance(details, dict):
        return dict(details)
    return None


async def _request_json_data(
    *,
    api_url: str,
    method: str,
    route: str,
    token: str | None = None,
    json_body: dict[str, Any] | None = None,
) -> Any:
    response = await _send_request(
        api_url=api_url,
        method=method,
        route=route,
        token=token,
        json_body=json_body,
    )
    if response.status_code >= 400:
        detail, _ = _error_payload(response)
        raise click.ClickException(f"{response.status_code}: {detail}")
    payload = response.json()
    if isinstance(payload, dict) and "data" in payload:
        return payload["data"]
    return payload


async def _complete_auth_challenge(*, api_url: str, challenge: dict[str, Any]) -> None:
    username = str(challenge.get("account_id", "")).strip()
    if not username:
        username = click.prompt("Apple ID", type=str).strip()
    password = click.prompt(f"Password for {username}", hide_input=True, type=str)
    auth_result = await _request_json_data(
        api_url=api_url,
        method="POST",
        route="/v1/auth/login",
        json_body={"username": username, "password": password},
    )
    if isinstance(auth_result, dict) and auth_result.get("status") == "challenge_required":
        challenge_id = str(auth_result.get("challenge_id", "")).strip()
        if not challenge_id:
            raise click.ClickException("Auth challenge response is missing challenge_id")
        code = click.prompt("Security code", type=str).strip()
        auth_result = await _request_json_data(
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
        _save_token(str(token))


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
    response = await _send_request(
        api_url=api_url,
        method=method,
        route=route,
        token=token,
        json_body=json_body,
        params=params,
        files=files,
    )

    if response.status_code >= 400:
        challenge = _auth_challenge_details(response)
        if (
            allow_challenge_retry
            and challenge is not None
            and not route.startswith("/v1/auth/")
            and method.strip().upper() not in {"HEAD", "OPTIONS"}
        ):
            await _complete_auth_challenge(api_url=api_url, challenge=challenge)
            refreshed_token = _load_token()
            if not refreshed_token:
                raise click.ClickException("Auth challenge completed but no local token was stored.")
            if method.strip().upper() not in {"GET"}:
                should_retry = click.confirm(
                    "Authentication challenge completed. Retry previous mutating operation?",
                    default=False,
                )
                if not should_retry:
                    raise click.ClickException("Operation was not retried.")
            response = await _send_request(
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
        detail, _ = _error_payload(response)
        raise click.ClickException(f"{response.status_code}: {detail}")

    if response.headers.get("content-type", "").startswith("application/json"):
        payload = response.json()
        if isinstance(payload, dict) and "data" in payload:
            return payload["data"]
        return payload
    return response.content


def _print_json(payload: Any) -> None:
    click.echo(json.dumps(payload, indent=2, sort_keys=True, default=str))


async def _observability_query(
    *,
    ctx: click.Context,
    language: str,
    query: str,
    source: str,
    start: int | None,
    end: int | None,
    step: str,
) -> Any:
    token = _load_token()
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

    return await _api_request(
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


@click.group(help="pyicloud API-driven CLI")
@click.option("--api-url", default=lambda: os.getenv("PYICLOUD_API_URL", DEFAULT_API_URL), show_default=True)
@click.pass_context
async def main(ctx: click.Context, api_url: str) -> None:
    ctx.ensure_object(dict)
    ctx.obj["api_url"] = api_url.rstrip("/")


@main.group()
async def auth() -> None:
    """Authentication commands."""


@auth.command("login")
@click.option("--username", required=True)
@click.option("--password", required=True, prompt=True, hide_input=True)
@click.pass_context
async def auth_login(ctx: click.Context, username: str, password: str) -> None:
    data = await _api_request(
        api_url=ctx.obj["api_url"],
        method="POST",
        route="/v1/auth/login",
        json_body={"username": username, "password": password},
    )
    token = data.get("access_token") if isinstance(data, dict) else None
    if token:
        _save_token(str(token))
    _print_json(data)


@auth.command("security-code")
@click.option("--challenge-id", required=True)
@click.option("--code", required=True)
@click.option("--password", required=True, prompt=True, hide_input=True)
@click.pass_context
async def auth_security_code(ctx: click.Context, challenge_id: str, code: str, password: str) -> None:
    data = await _api_request(
        api_url=ctx.obj["api_url"],
        method="POST",
        route="/v1/auth/security-code",
        json_body={"challenge_id": challenge_id, "code": code, "password": password},
    )
    token = data.get("access_token") if isinstance(data, dict) else None
    if token:
        _save_token(str(token))
    _print_json(data)


@auth.command("session")
@click.pass_context
async def auth_session(ctx: click.Context) -> None:
    token = _load_token()
    if token is None:
        raise click.ClickException("No local token found. Run `icloud auth login` first.")
    data = await _api_request(api_url=ctx.obj["api_url"], method="GET", route="/v1/auth/session", token=token)
    _print_json(data)


@auth.command("logout")
@click.pass_context
async def auth_logout(ctx: click.Context) -> None:
    token = _load_token()
    if token is None:
        raise click.ClickException("No local token found.")
    data = await _api_request(api_url=ctx.obj["api_url"], method="POST", route="/v1/auth/logout", token=token)
    _clear_token()
    _print_json(data)


@main.group()
async def devices() -> None:
    """Find My iPhone device commands."""


@devices.command("list")
@click.pass_context
async def devices_list(ctx: click.Context) -> None:
    token = _load_token()
    if token is None:
        raise click.ClickException("No local token found. Run `icloud auth login` first.")
    data = await _api_request(api_url=ctx.obj["api_url"], method="GET", route="/v1/devices", token=token)
    _print_json(data)


@devices.command("location")
@click.argument("device_id")
@click.pass_context
async def devices_location(ctx: click.Context, device_id: str) -> None:
    token = _load_token()
    if token is None:
        raise click.ClickException("No local token found. Run `icloud auth login` first.")
    data = await _api_request(
        api_url=ctx.obj["api_url"],
        method="GET",
        route=f"/v1/devices/{device_id}/location",
        token=token,
    )
    _print_json(data)


@devices.command("status")
@click.argument("device_id")
@click.pass_context
async def devices_status(ctx: click.Context, device_id: str) -> None:
    token = _load_token()
    if token is None:
        raise click.ClickException("No local token found. Run `icloud auth login` first.")
    data = await _api_request(
        api_url=ctx.obj["api_url"],
        method="GET",
        route=f"/v1/devices/{device_id}/status",
        token=token,
    )
    _print_json(data)


@devices.command("play-sound")
@click.argument("device_id")
@click.option("--subject", default="Find My iPhone Alert", show_default=True)
@click.pass_context
async def devices_play_sound(ctx: click.Context, device_id: str, subject: str) -> None:
    token = _load_token()
    if token is None:
        raise click.ClickException("No local token found. Run `icloud auth login` first.")
    data = await _api_request(
        api_url=ctx.obj["api_url"],
        method="POST",
        route=f"/v1/devices/{device_id}/actions/play-sound",
        token=token,
        json_body={"subject": subject},
    )
    _print_json(data)


@devices.command("message")
@click.argument("device_id")
@click.option("--subject", default="Find My iPhone Alert", show_default=True)
@click.option("--message", required=True)
@click.option("--sounds/--no-sounds", default=False)
@click.pass_context
async def devices_message(ctx: click.Context, device_id: str, subject: str, message: str, sounds: bool) -> None:
    token = _load_token()
    if token is None:
        raise click.ClickException("No local token found. Run `icloud auth login` first.")
    data = await _api_request(
        api_url=ctx.obj["api_url"],
        method="POST",
        route=f"/v1/devices/{device_id}/actions/message",
        token=token,
        json_body={"subject": subject, "message": message, "sounds": sounds},
    )
    _print_json(data)


@devices.command("lost-mode")
@click.argument("device_id")
@click.option("--number", required=True)
@click.option("--text", default="This iPhone has been lost. Please call me.", show_default=True)
@click.option("--newpasscode", default="", show_default=True)
@click.pass_context
async def devices_lost_mode(ctx: click.Context, device_id: str, number: str, text: str, newpasscode: str) -> None:
    token = _load_token()
    if token is None:
        raise click.ClickException("No local token found. Run `icloud auth login` first.")
    data = await _api_request(
        api_url=ctx.obj["api_url"],
        method="POST",
        route=f"/v1/devices/{device_id}/actions/lost-mode",
        token=token,
        json_body={"number": number, "text": text, "newpasscode": newpasscode},
    )
    _print_json(data)


@main.group()
async def account() -> None:
    """Account commands."""


@account.command("devices")
@click.pass_context
async def account_devices(ctx: click.Context) -> None:
    token = _load_token()
    if token is None:
        raise click.ClickException("No local token found. Run `icloud auth login` first.")
    data = await _api_request(api_url=ctx.obj["api_url"], method="GET", route="/v1/account/devices", token=token)
    _print_json(data)


@account.command("family")
@click.pass_context
async def account_family(ctx: click.Context) -> None:
    token = _load_token()
    if token is None:
        raise click.ClickException("No local token found. Run `icloud auth login` first.")
    data = await _api_request(api_url=ctx.obj["api_url"], method="GET", route="/v1/account/family", token=token)
    _print_json(data)


@account.command("storage")
@click.pass_context
async def account_storage(ctx: click.Context) -> None:
    token = _load_token()
    if token is None:
        raise click.ClickException("No local token found. Run `icloud auth login` first.")
    data = await _api_request(api_url=ctx.obj["api_url"], method="GET", route="/v1/account/storage", token=token)
    _print_json(data)


@main.group()
async def calendar() -> None:
    """Calendar commands."""


@calendar.command("calendars")
@click.pass_context
async def calendar_calendars(ctx: click.Context) -> None:
    token = _load_token()
    if token is None:
        raise click.ClickException("No local token found. Run `icloud auth login` first.")
    data = await _api_request(api_url=ctx.obj["api_url"], method="GET", route="/v1/calendar/calendars", token=token)
    _print_json(data)


@calendar.command("events")
@click.option("--from-dt", default="", help="ISO datetime start boundary.")
@click.option("--to-dt", default="", help="ISO datetime end boundary.")
@click.pass_context
async def calendar_events(ctx: click.Context, from_dt: str, to_dt: str) -> None:
    token = _load_token()
    if token is None:
        raise click.ClickException("No local token found. Run `icloud auth login` first.")
    params: dict[str, Any] = {}
    if from_dt:
        params["from_dt"] = from_dt
    if to_dt:
        params["to_dt"] = to_dt
    data = await _api_request(
        api_url=ctx.obj["api_url"],
        method="GET",
        route="/v1/calendar/events",
        token=token,
        params=params or None,
    )
    _print_json(data)


@calendar.command("event-detail")
@click.option("--calendar-guid", required=True)
@click.option("--event-guid", required=True)
@click.pass_context
async def calendar_event_detail(ctx: click.Context, calendar_guid: str, event_guid: str) -> None:
    token = _load_token()
    if token is None:
        raise click.ClickException("No local token found. Run `icloud auth login` first.")
    data = await _api_request(
        api_url=ctx.obj["api_url"],
        method="GET",
        route="/v1/calendar/event-detail",
        token=token,
        params={"calendar_guid": calendar_guid, "event_guid": event_guid},
    )
    _print_json(data)


@main.group()
async def contacts() -> None:
    """Contacts commands."""


@contacts.command("list")
@click.pass_context
async def contacts_list(ctx: click.Context) -> None:
    token = _load_token()
    if token is None:
        raise click.ClickException("No local token found. Run `icloud auth login` first.")
    data = await _api_request(api_url=ctx.obj["api_url"], method="GET", route="/v1/contacts", token=token)
    _print_json(data)


@main.group()
async def reminders() -> None:
    """Reminders commands."""


@reminders.command("list")
@click.pass_context
async def reminders_list(ctx: click.Context) -> None:
    token = _load_token()
    if token is None:
        raise click.ClickException("No local token found. Run `icloud auth login` first.")
    data = await _api_request(api_url=ctx.obj["api_url"], method="GET", route="/v1/reminders", token=token)
    _print_json(data)


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
    token = _load_token()
    if token is None:
        raise click.ClickException("No local token found. Run `icloud auth login` first.")
    payload: dict[str, Any] = {"title": title, "description": description}
    if collection:
        payload["collection"] = collection
    if due_date:
        payload["due_date"] = due_date
    data = await _api_request(
        api_url=ctx.obj["api_url"],
        method="POST",
        route="/v1/reminders",
        token=token,
        json_body=payload,
    )
    _print_json(data)


@main.group()
async def photos() -> None:
    """Photos commands."""


@photos.command("albums")
@click.pass_context
async def photos_albums(ctx: click.Context) -> None:
    token = _load_token()
    if token is None:
        raise click.ClickException("No local token found. Run `icloud auth login` first.")
    data = await _api_request(api_url=ctx.obj["api_url"], method="GET", route="/v1/photos/albums", token=token)
    _print_json(data)


@photos.command("assets")
@click.option("--album", default="All Photos", show_default=True)
@click.option("--limit", default=100, show_default=True, type=int)
@click.option("--offset", default=0, show_default=True, type=int)
@click.pass_context
async def photos_assets(ctx: click.Context, album: str, limit: int, offset: int) -> None:
    token = _load_token()
    if token is None:
        raise click.ClickException("No local token found. Run `icloud auth login` first.")
    data = await _api_request(
        api_url=ctx.obj["api_url"],
        method="GET",
        route="/v1/photos/assets",
        token=token,
        params={"album": album, "limit": limit, "offset": offset},
    )
    _print_json(data)


@photos.command("asset")
@click.option("--asset-id", required=True)
@click.option("--album", default="All Photos", show_default=True)
@click.pass_context
async def photos_asset(ctx: click.Context, asset_id: str, album: str) -> None:
    token = _load_token()
    if token is None:
        raise click.ClickException("No local token found. Run `icloud auth login` first.")
    data = await _api_request(
        api_url=ctx.obj["api_url"],
        method="GET",
        route="/v1/photos/asset",
        token=token,
        params={"asset_id": asset_id, "album": album},
    )
    _print_json(data)


@photos.command("download")
@click.option("--asset-id", required=True)
@click.option("--album", default="All Photos", show_default=True)
@click.option("--version", default="original", show_default=True)
@click.option("--download-to", required=True, type=click.Path(dir_okay=False, path_type=Path))
@click.pass_context
async def photos_download(ctx: click.Context, asset_id: str, album: str, version: str, download_to: Path) -> None:
    token = _load_token()
    if token is None:
        raise click.ClickException("No local token found. Run `icloud auth login` first.")
    content = await _api_request(
        api_url=ctx.obj["api_url"],
        method="GET",
        route="/v1/photos/download",
        token=token,
        params={"asset_id": asset_id, "album": album, "version": version},
    )
    output = Path(download_to)
    output.parent.mkdir(parents=True, exist_ok=True)
    assert isinstance(content, bytes | bytearray), "Expected binary response from download endpoint"
    output.write_bytes(bytes(content))
    _print_json({"ok": True, "detail": f"Downloaded to {output}"})


@main.group()
async def ubiquity() -> None:
    """Ubiquity file library commands."""


@ubiquity.command("tree")
@click.option("--path", default="/", show_default=True)
@click.pass_context
async def ubiquity_tree(ctx: click.Context, path: str) -> None:
    token = _load_token()
    if token is None:
        raise click.ClickException("No local token found. Run `icloud auth login` first.")
    data = await _api_request(
        api_url=ctx.obj["api_url"],
        method="GET",
        route="/v1/ubiquity/tree",
        token=token,
        params={"path": path},
    )
    _print_json(data)


@ubiquity.command("file")
@click.option("--path", required=True)
@click.option("--download-to", default="", help="If set, download file bytes to this path.")
@click.pass_context
async def ubiquity_file(ctx: click.Context, path: str, download_to: str) -> None:
    token = _load_token()
    if token is None:
        raise click.ClickException("No local token found. Run `icloud auth login` first.")
    if not download_to:
        data = await _api_request(
            api_url=ctx.obj["api_url"],
            method="GET",
            route="/v1/ubiquity/file",
            token=token,
            params={"path": path, "download": "false"},
        )
        _print_json(data)
        return

    content = await _api_request(
        api_url=ctx.obj["api_url"],
        method="GET",
        route="/v1/ubiquity/file",
        token=token,
        params={"path": path, "download": "true"},
    )
    output = Path(download_to)
    output.parent.mkdir(parents=True, exist_ok=True)
    assert isinstance(content, bytes | bytearray), "Expected binary response from download endpoint"
    output.write_bytes(bytes(content))
    _print_json({"ok": True, "detail": f"Downloaded to {output}"})


@main.group()
async def drive() -> None:
    """Drive commands."""


@drive.command("tree")
@click.option("--path", default="/", show_default=True)
@click.pass_context
async def drive_tree(ctx: click.Context, path: str) -> None:
    token = _load_token()
    if token is None:
        raise click.ClickException("No local token found. Run `icloud auth login` first.")
    data = await _api_request(
        api_url=ctx.obj["api_url"],
        method="GET",
        route="/v1/drive/tree",
        token=token,
        params={"path": path},
    )
    _print_json(data)


@drive.command("file")
@click.option("--path", required=True)
@click.option("--download-to", default="", help="If set, download file bytes to this path.")
@click.pass_context
async def drive_file(ctx: click.Context, path: str, download_to: str) -> None:
    token = _load_token()
    if token is None:
        raise click.ClickException("No local token found. Run `icloud auth login` first.")

    if not download_to:
        data = await _api_request(
            api_url=ctx.obj["api_url"],
            method="GET",
            route="/v1/drive/file",
            token=token,
            params={"path": path, "download": "false"},
        )
        _print_json(data)
        return

    content = await _api_request(
        api_url=ctx.obj["api_url"],
        method="GET",
        route="/v1/drive/file",
        token=token,
        params={"path": path, "download": "true"},
    )
    output = Path(download_to)
    output.parent.mkdir(parents=True, exist_ok=True)
    assert isinstance(content, bytes | bytearray), "Expected binary response from download endpoint"
    output.write_bytes(bytes(content))
    _print_json({"ok": True, "detail": f"Downloaded to {output}"})


@drive.command("mkdir")
@click.option("--parent-path", default="/", show_default=True)
@click.option("--name", required=True)
@click.pass_context
async def drive_mkdir(ctx: click.Context, parent_path: str, name: str) -> None:
    token = _load_token()
    if token is None:
        raise click.ClickException("No local token found. Run `icloud auth login` first.")
    data = await _api_request(
        api_url=ctx.obj["api_url"],
        method="POST",
        route="/v1/drive/folders",
        token=token,
        json_body={"parent_path": parent_path, "name": name},
    )
    _print_json(data)


@drive.command("upload")
@click.option("--parent-path", default="/", show_default=True)
@click.option("--file", "file_path", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.pass_context
async def drive_upload(ctx: click.Context, parent_path: str, file_path: Path) -> None:
    token = _load_token()
    if token is None:
        raise click.ClickException("No local token found. Run `icloud auth login` first.")

    files = {"file": (file_path.name, file_path.read_bytes(), "application/octet-stream")}
    data = await _api_request(
        api_url=ctx.obj["api_url"],
        method="POST",
        route="/v1/drive/upload",
        token=token,
        params={"parent_path": parent_path},
        files=files,
    )
    _print_json(data)


@drive.command("rename")
@click.option("--path", required=True)
@click.option("--new-name", required=True)
@click.pass_context
async def drive_rename(ctx: click.Context, path: str, new_name: str) -> None:
    token = _load_token()
    if token is None:
        raise click.ClickException("No local token found. Run `icloud auth login` first.")
    data = await _api_request(
        api_url=ctx.obj["api_url"],
        method="PATCH",
        route="/v1/drive/node",
        token=token,
        json_body={"path": path, "new_name": new_name},
    )
    _print_json(data)


@drive.command("delete")
@click.option("--path", required=True)
@click.pass_context
async def drive_delete(ctx: click.Context, path: str) -> None:
    token = _load_token()
    if token is None:
        raise click.ClickException("No local token found. Run `icloud auth login` first.")
    data = await _api_request(
        api_url=ctx.obj["api_url"],
        method="DELETE",
        route="/v1/drive/node",
        token=token,
        params={"path": path},
    )
    _print_json(data)


@main.group()
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
    )
    _print_json(data)


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
    )
    _print_json(data)


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
    )
    _print_json(data)


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
    )
    events = _extract_flow_events(data)
    if output_format == "json":
        _print_json({"flow_id": flow_id, "events": events})
        return
    _print_flow_table(flow_id=flow_id, events=events)


if __name__ == "__main__":
    main()
