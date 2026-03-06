"""Drive CLI command group registration."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import asyncclick as click

ApiRequest = Callable[..., Awaitable[Any]]
LoadToken = Callable[[], str | None]
PrintJson = Callable[[Any], None]


def register_drive_commands(
    main_group: click.Group,
    *,
    load_token: LoadToken,
    api_request: ApiRequest,
    print_json: PrintJson,
) -> None:
    """Register the `drive` command group under the main CLI."""

    @main_group.group()
    async def drive() -> None:
        """Drive commands."""

    @drive.command("tree")
    @click.option("--path", default="/", show_default=True)
    @click.pass_context
    async def drive_tree(ctx: click.Context, path: str) -> None:
        token = load_token()
        if token is None:
            raise click.ClickException("No local token found. Run `icloud auth login` first.")
        data = await api_request(
            api_url=ctx.obj["api_url"],
            method="GET",
            route="/v1/drive/tree",
            token=token,
            params={"path": path},
        )
        print_json(data)

    @drive.command("file")
    @click.option("--path", required=True)
    @click.option("--download-to", default="", help="If set, download file bytes to this path.")
    @click.pass_context
    async def drive_file(ctx: click.Context, path: str, download_to: str) -> None:
        token = load_token()
        if token is None:
            raise click.ClickException("No local token found. Run `icloud auth login` first.")

        if not download_to:
            data = await api_request(
                api_url=ctx.obj["api_url"],
                method="GET",
                route="/v1/drive/file",
                token=token,
                params={"path": path, "download": "false"},
            )
            print_json(data)
            return

        content = await api_request(
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
        print_json({"ok": True, "detail": f"Downloaded to {output}"})

    @drive.command("mkdir")
    @click.option("--parent-path", default="/", show_default=True)
    @click.option("--name", required=True)
    @click.pass_context
    async def drive_mkdir(ctx: click.Context, parent_path: str, name: str) -> None:
        token = load_token()
        if token is None:
            raise click.ClickException("No local token found. Run `icloud auth login` first.")
        data = await api_request(
            api_url=ctx.obj["api_url"],
            method="POST",
            route="/v1/drive/folders",
            token=token,
            json_body={"parent_path": parent_path, "name": name},
        )
        print_json(data)

    @drive.command("upload")
    @click.option("--parent-path", default="/", show_default=True)
    @click.option(
        "--file",
        "file_path",
        required=True,
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
    )
    @click.pass_context
    async def drive_upload(ctx: click.Context, parent_path: str, file_path: Path) -> None:
        token = load_token()
        if token is None:
            raise click.ClickException("No local token found. Run `icloud auth login` first.")

        files = {"file": (file_path.name, file_path.read_bytes(), "application/octet-stream")}
        data = await api_request(
            api_url=ctx.obj["api_url"],
            method="POST",
            route="/v1/drive/upload",
            token=token,
            params={"parent_path": parent_path},
            files=files,
        )
        print_json(data)

    @drive.command("rename")
    @click.option("--path", required=True)
    @click.option("--new-name", required=True)
    @click.pass_context
    async def drive_rename(ctx: click.Context, path: str, new_name: str) -> None:
        token = load_token()
        if token is None:
            raise click.ClickException("No local token found. Run `icloud auth login` first.")
        data = await api_request(
            api_url=ctx.obj["api_url"],
            method="PATCH",
            route="/v1/drive/node",
            token=token,
            json_body={"path": path, "new_name": new_name},
        )
        print_json(data)

    @drive.command("delete")
    @click.option("--path", required=True)
    @click.pass_context
    async def drive_delete(ctx: click.Context, path: str) -> None:
        token = load_token()
        if token is None:
            raise click.ClickException("No local token found. Run `icloud auth login` first.")
        data = await api_request(
            api_url=ctx.obj["api_url"],
            method="DELETE",
            route="/v1/drive/node",
            token=token,
            params={"path": path},
        )
        print_json(data)
