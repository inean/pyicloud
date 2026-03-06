"""Ubiquity CLI command group registration."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import asyncclick as click

ApiRequest = Callable[..., Awaitable[Any]]
LoadToken = Callable[[], str | None]
PrintJson = Callable[[Any], None]


def register_ubiquity_commands(
    main_group: click.Group,
    *,
    load_token: LoadToken,
    api_request: ApiRequest,
    print_json: PrintJson,
) -> None:
    """Register the `ubiquity` command group under the main CLI."""

    @main_group.group()
    async def ubiquity() -> None:
        """Ubiquity file library commands."""

    @ubiquity.command("tree")
    @click.option("--path", default="/", show_default=True)
    @click.pass_context
    async def ubiquity_tree(ctx: click.Context, path: str) -> None:
        token = load_token()
        if token is None:
            raise click.ClickException("No local token found. Run `icloud auth login` first.")
        data = await api_request(
            api_url=ctx.obj["api_url"],
            method="GET",
            route="/v1/ubiquity/tree",
            token=token,
            params={"path": path},
        )
        print_json(data)

    @ubiquity.command("file")
    @click.option("--path", required=True)
    @click.option("--download-to", default="", help="If set, download file bytes to this path.")
    @click.pass_context
    async def ubiquity_file(ctx: click.Context, path: str, download_to: str) -> None:
        token = load_token()
        if token is None:
            raise click.ClickException("No local token found. Run `icloud auth login` first.")
        if not download_to:
            data = await api_request(
                api_url=ctx.obj["api_url"],
                method="GET",
                route="/v1/ubiquity/file",
                token=token,
                params={"path": path, "download": "false"},
            )
            print_json(data)
            return

        content = await api_request(
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
        print_json({"ok": True, "detail": f"Downloaded to {output}"})
