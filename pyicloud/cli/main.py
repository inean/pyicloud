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


async def _api_request(
    *,
    api_url: str,
    method: str,
    route: str,
    token: str | None = None,
    json_body: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
    files: dict[str, Any] | None = None,
) -> Any:
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    async with httpx.AsyncClient(base_url=api_url, timeout=30.0) as client:
        response = await client.request(
            method,
            route,
            headers=headers,
            json=json_body,
            params=params,
            files=files,
        )

    if response.status_code >= 400:
        detail = response.text
        try:
            payload = response.json()
            detail = str(payload.get("detail", payload))
        except Exception:  # noqa: BLE001
            pass
        raise click.ClickException(f"{response.status_code}: {detail}")

    if response.headers.get("content-type", "").startswith("application/json"):
        return response.json()
    return response.content


def _print_json(payload: Any) -> None:
    click.echo(json.dumps(payload, indent=2, sort_keys=True, default=str))


def _normalize_observability_language(language: str) -> str:
    clean = language.strip().lower()
    return "promql" if clean == "pronql" else clean


async def _observability_query(
    *,
    ctx: click.Context,
    language: str,
    query: str,
    source: str,
    start: int | None,
    end: int | None,
    step: str,
) -> None:
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

    data = await _api_request(
        api_url=ctx.obj["api_url"],
        method="POST",
        route=f"/v1/observability/{_normalize_observability_language(language)}",
        token=token,
        json_body=payload,
    )
    _print_json(data)


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
@click.pass_context
async def auth_security_code(ctx: click.Context, challenge_id: str, code: str) -> None:
    data = await _api_request(
        api_url=ctx.obj["api_url"],
        method="POST",
        route="/v1/auth/security-code",
        json_body={"challenge_id": challenge_id, "code": code},
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
    await _observability_query(
        ctx=ctx,
        language="promql",
        query=query,
        source=source,
        start=start,
        end=end,
        step=step,
    )


@observability.command("pronql", hidden=True)
@click.option("--query", required=True)
@click.option("--source", default="", show_default=False)
@click.option("--start", type=int, default=None, show_default=False)
@click.option("--end", type=int, default=None, show_default=False)
@click.option("--step", default="", show_default=False)
@click.pass_context
async def observability_pronql(
    ctx: click.Context,
    query: str,
    source: str,
    start: int | None,
    end: int | None,
    step: str,
) -> None:
    await _observability_query(
        ctx=ctx,
        language="pronql",
        query=query,
        source=source,
        start=start,
        end=end,
        step=step,
    )


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
    await _observability_query(
        ctx=ctx,
        language="traceql",
        query=query,
        source=source,
        start=start,
        end=end,
        step=step,
    )


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
    await _observability_query(
        ctx=ctx,
        language="logql",
        query=query,
        source=source,
        start=start,
        end=end,
        step=step,
    )


if __name__ == "__main__":
    main()
