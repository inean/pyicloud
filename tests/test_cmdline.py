"""Cmdline tests."""

from __future__ import annotations

import os
import pickle
from unittest import IsolatedAsyncioTestCase
from unittest.mock import patch

import pytest
from asyncclick.testing import CliRunner

from pyicloud import cmdline

from . import PyiCloudMock
from .const import AUTHENTICATED_USER, REQUIRES_2FA_USER, VALID_2FA_CODE, VALID_PASSWORD
from .const_findmyiphone import FMI_FAMILY_WORKING


class TestCmdline(IsolatedAsyncioTestCase):
    """Cmdline test cases."""

    def setUp(self):
        """Set up tests."""
        cmdline.PyiCloud = PyiCloudMock
        self.main = cmdline.main

    @pytest.mark.anyio
    async def test_no_arg(self):
        """Test no args."""
        runner = CliRunner()

        result = await runner.invoke(self.main)
        assert result.exit_code == 2

        result = await runner.invoke(self.main, args=[])
        assert result.exit_code == 2

    @pytest.mark.anyio
    async def test_help(self):
        """Test the help command."""
        runner = CliRunner()

        result = await runner.invoke(self.main, ["--help"])
        assert result.exit_code == 0

    @pytest.mark.anyio
    async def test_username(self):
        """Test the username command."""
        # No username supplied
        runner = CliRunner()

        result = await runner.invoke(self.main, ["--username"])
        assert result.exit_code == 2

    @pytest.mark.anyio
    async def test_username_password_invalid(self):  # pylint: disable=unused-argument
        """Test username and password commands."""
        # Bad username or password
        runner = CliRunner()

        result = await runner.invoke(self.main, ["--username", "invalid_user"])
        assert "Bad username or password for invalid_user" in str(result.exception)

        # We should not use getpass for this one, but we reset the password at login fail
        result = await runner.invoke(self.main, ["--username", "invalid_user", "--password", "invalid_pass"])
        assert "Bad username or password for invalid_user" in str(result.exception)

    @pytest.mark.anyio
    @patch("pyicloud.cmdline.input")
    async def test_username_password_requires_2fa(self, mock_input):  # pylint: disable=unused-argument
        """Test username and password commands."""
        # Valid connection for the first time
        mock_input.return_value = VALID_2FA_CODE
        runner = CliRunner()

        result = await runner.invoke(
            self.main,
            [
                "--username",
                REQUIRES_2FA_USER,
                "--password",
                VALID_PASSWORD,
                "--non-interactive",
            ],
        )
        assert result.exit_code == 0

    @pytest.mark.anyio
    async def test_device_outputfile(self):  # pylint: disable=unused-argument
        """Test the outputfile command."""
        runner = CliRunner()

        result = await runner.invoke(
            self.main,
            ["--username", AUTHENTICATED_USER, "--password", VALID_PASSWORD, "--non-interactive", "--outputfile"],
        )
        assert result.exit_code == 0

        devices = FMI_FAMILY_WORKING.get("content")
        if devices:
            for device in devices:
                file_name = device.get("name").strip().lower() + ".fmip_snapshot"

                pickle_file = open(file_name, "rb")
                assert pickle_file

                contents = []
                with pickle_file as opened_file:
                    while True:
                        try:
                            contents.append(pickle.load(opened_file))
                        except EOFError:
                            break
                assert contents == [device]

                pickle_file.close()
                os.remove(file_name)
