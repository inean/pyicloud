#! /usr/bin/env python
"""Legacy flat CLI compatibility shim."""

from __future__ import annotations

import asyncclick as click

MIGRATION_GUIDE = """Legacy flat CLI flags are retired.

Use the API-first subcommand CLI instead:
  icloud auth login --username <apple-id> --password <password>
  icloud devices list
  icloud devices location <device-id>
  icloud devices play-sound <device-id>
  icloud devices message <device-id> --message "..."
  icloud devices lost-mode <device-id> --number <phone> --text "..." --newpasscode <code>
  icloud account devices
  icloud account family
  icloud account storage
  icloud drive tree --path /

Migration examples from old flags:
  --list                    -> icloud devices list
  --locate --device <id>    -> icloud devices location <id>
  --sound --device <id>     -> icloud devices play-sound <id>
  --message --device <id>   -> icloud devices message <id> --message "..."
  --lostmode --device <id>  -> icloud devices lost-mode <id> --number ... --text ... --newpasscode ...
"""


@click.command(
    name="icloud",
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
    help="Deprecated legacy CLI shim. Use `icloud --help` for the new subcommand CLI.",
)
@click.pass_context
async def main(ctx: click.Context) -> None:
    """Show migration guidance for users still invoking the legacy flat CLI."""
    if not ctx.args:
        click.echo(MIGRATION_GUIDE)
        return

    legacy_args = " ".join(ctx.args)
    raise click.ClickException(f"{MIGRATION_GUIDE}\n\nReceived legacy-style args: {legacy_args}")


if __name__ == "__main__":
    main()
