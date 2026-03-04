"""Legacy cmdline compatibility tests."""

from __future__ import annotations

import pytest
from asyncclick.testing import CliRunner

from pyicloud import cmdline


@pytest.mark.asyncio
async def test_help_exposes_deprecation_notice():
    runner = CliRunner()
    result = await runner.invoke(cmdline.main, ["--help"])

    assert result.exit_code == 0
    assert "Deprecated legacy CLI shim" in result.output


@pytest.mark.asyncio
async def test_no_args_prints_migration_guide():
    runner = CliRunner()
    result = await runner.invoke(cmdline.main, [])

    assert result.exit_code == 0
    assert "Legacy flat CLI flags are retired." in result.output
    assert "icloud devices list" in result.output


@pytest.mark.asyncio
async def test_legacy_style_flags_raise_with_migration_guide():
    runner = CliRunner()
    result = await runner.invoke(cmdline.main, ["--username", "user@example.com", "--list"])

    assert result.exit_code != 0
    assert "Legacy flat CLI flags are retired." in result.output
    assert "Received legacy-style args:" in result.output
