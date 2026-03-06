"""Photos CLI command group registration."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import asyncclick as click

ApiRequest = Callable[..., Awaitable[Any]]
LoadToken = Callable[[], str | None]
PrintJson = Callable[[Any], None]


def register_photos_commands(
    main_group: click.Group,
    *,
    load_token: LoadToken,
    api_request: ApiRequest,
    print_json: PrintJson,
) -> None:
    """Register the `photos` command group under the main CLI."""

    @main_group.group()
    async def photos() -> None:
        """Photos commands."""

    @photos.command("albums")
    @click.pass_context
    async def photos_albums(ctx: click.Context) -> None:
        token = load_token()
        if token is None:
            raise click.ClickException("No local token found. Run `icloud auth login` first.")
        data = await api_request(api_url=ctx.obj["api_url"], method="GET", route="/v1/photos/albums", token=token)
        print_json(data)

    @photos.command("assets")
    @click.option("--album", default="All Photos", show_default=True)
    @click.option("--limit", default=100, show_default=True, type=int)
    @click.option("--offset", default=0, show_default=True, type=int)
    @click.pass_context
    async def photos_assets(ctx: click.Context, album: str, limit: int, offset: int) -> None:
        token = load_token()
        if token is None:
            raise click.ClickException("No local token found. Run `icloud auth login` first.")
        data = await api_request(
            api_url=ctx.obj["api_url"],
            method="GET",
            route="/v1/photos/assets",
            token=token,
            params={"album": album, "limit": limit, "offset": offset},
        )
        print_json(data)

    @photos.command("asset")
    @click.option("--asset-id", required=True)
    @click.option("--album", default="All Photos", show_default=True)
    @click.pass_context
    async def photos_asset(ctx: click.Context, asset_id: str, album: str) -> None:
        token = load_token()
        if token is None:
            raise click.ClickException("No local token found. Run `icloud auth login` first.")
        data = await api_request(
            api_url=ctx.obj["api_url"],
            method="GET",
            route="/v1/photos/asset",
            token=token,
            params={"asset_id": asset_id, "album": album},
        )
        print_json(data)

    @photos.command("download")
    @click.option("--asset-id", required=True)
    @click.option("--album", default="All Photos", show_default=True)
    @click.option("--version", default="original", show_default=True)
    @click.option("--download-to", required=True, type=click.Path(dir_okay=False, path_type=Path))
    @click.pass_context
    async def photos_download(ctx: click.Context, asset_id: str, album: str, version: str, download_to: Path) -> None:
        token = load_token()
        if token is None:
            raise click.ClickException("No local token found. Run `icloud auth login` first.")
        content = await api_request(
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
        print_json({"ok": True, "detail": f"Downloaded to {output}"})
